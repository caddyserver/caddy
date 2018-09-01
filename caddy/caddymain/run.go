// Copyright 2015 Light Code Labs, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddymain

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/klauspost/cpuid"
	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddytls"
	"github.com/mholt/caddy/telemetry"
	"github.com/xenolf/lego/acmev2"
	"gopkg.in/natefinch/lumberjack.v2"

	_ "github.com/mholt/caddy/caddyhttp" // plug in the HTTP server type
	// This is where other plugins get plugged in (imported)
)

func init() {
	caddy.TrapSignals()
	setVersion()

	flag.BoolVar(&caddytls.Agreed, "agree", false, "Agree to the CA's Subscriber Agreement")
	flag.StringVar(&caddytls.DefaultCAUrl, "ca", "https://acme-v02.api.letsencrypt.org/directory", "URL to certificate authority's ACME server directory")
	flag.BoolVar(&caddytls.DisableHTTPChallenge, "disable-http-challenge", caddytls.DisableHTTPChallenge, "Disable the ACME HTTP challenge")
	flag.BoolVar(&caddytls.DisableTLSSNIChallenge, "disable-tls-sni-challenge", caddytls.DisableTLSSNIChallenge, "Disable the ACME TLS-SNI challenge")
	flag.StringVar(&disabledMetrics, "disabled-metrics", "", "Comma-separated list of telemetry metrics to disable")
	flag.StringVar(&conf, "conf", "", "Caddyfile to load (default \""+caddy.DefaultConfigFile+"\")")
	flag.StringVar(&cpu, "cpu", "100%", "CPU cap")
	flag.StringVar(&envFile, "env", "", "Path to file with environment variables to load in KEY=VALUE format")
	flag.BoolVar(&plugins, "plugins", false, "List installed plugins")
	flag.StringVar(&caddytls.DefaultEmail, "email", "", "Default ACME CA account email address")
	flag.DurationVar(&acme.HTTPClient.Timeout, "catimeout", acme.HTTPClient.Timeout, "Default ACME CA HTTP timeout")
	flag.StringVar(&logfile, "log", "", "Process log file")
	flag.StringVar(&caddy.PidFile, "pidfile", "", "Path to write pid file")
	flag.BoolVar(&caddy.Quiet, "quiet", false, "Quiet mode (no initialization output)")
	flag.StringVar(&revoke, "revoke", "", "Hostname for which to revoke the certificate")
	flag.StringVar(&serverType, "type", "http", "Type of server to run")
	flag.BoolVar(&version, "version", false, "Show version")
	flag.BoolVar(&validate, "validate", false, "Parse the Caddyfile but do not start the server")

	caddy.RegisterCaddyfileLoader("flag", caddy.LoaderFunc(confLoader))
	caddy.SetDefaultCaddyfileLoader("default", caddy.LoaderFunc(defaultLoader))
}

// Run is Caddy's main() function.
func Run() {
	flag.Parse()

	caddy.AppName = appName
	caddy.AppVersion = appVersion
	acme.UserAgent = appName + "/" + appVersion

	// Set up process log before anything bad happens
	switch logfile {
	case "stdout":
		log.SetOutput(os.Stdout)
	case "stderr":
		log.SetOutput(os.Stderr)
	case "":
		log.SetOutput(ioutil.Discard)
	default:
		log.SetOutput(&lumberjack.Logger{
			Filename:   logfile,
			MaxSize:    100,
			MaxAge:     14,
			MaxBackups: 10,
		})
	}

	//Load all additional envs as soon as possible
	if err := LoadEnvFromFile(envFile); err != nil {
		mustLogFatalf("%v", err)
	}

	// initialize telemetry client
	if EnableTelemetry {
		err := initTelemetry()
		if err != nil {
			mustLogFatalf("[ERROR] Initializing telemetry: %v", err)
		}
	} else if disabledMetrics != "" {
		mustLogFatalf("[ERROR] Cannot disable specific metrics because telemetry is disabled")
	}

	// Check for one-time actions
	if revoke != "" {
		err := caddytls.Revoke(revoke)
		if err != nil {
			mustLogFatalf("%v", err)
		}
		fmt.Printf("Revoked certificate for %s\n", revoke)
		os.Exit(0)
	}
	if version {
		fmt.Printf("%s %s (unofficial)\n", appName, appVersion)
		if devBuild && gitShortStat != "" {
			fmt.Printf("%s\n%s\n", gitShortStat, gitFilesModified)
		}
		os.Exit(0)
	}
	if plugins {
		fmt.Println(caddy.DescribePlugins())
		os.Exit(0)
	}

	// Set CPU cap
	err := setCPU(cpu)
	if err != nil {
		mustLogFatalf("%v", err)
	}

	// Executes Startup events
	caddy.EmitEvent(caddy.StartupEvent, nil)

	// Get Caddyfile input
	caddyfileinput, err := caddy.LoadCaddyfile(serverType)
	if err != nil {
		mustLogFatalf("%v", err)
	}

	if validate {
		err := caddy.ValidateAndExecuteDirectives(caddyfileinput, nil, true)
		if err != nil {
			mustLogFatalf("%v", err)
		}
		msg := "Caddyfile is valid"
		fmt.Println(msg)
		log.Printf("[INFO] %s", msg)
		os.Exit(0)
	}

	// Start your engines
	instance, err := caddy.Start(caddyfileinput)
	if err != nil {
		mustLogFatalf("%v", err)
	}

	// Execute instantiation events
	caddy.EmitEvent(caddy.InstanceStartupEvent, instance)

	// Begin telemetry (these are no-ops if telemetry disabled)
	telemetry.Set("caddy_version", appVersion)
	telemetry.Set("num_listeners", len(instance.Servers()))
	telemetry.Set("server_type", serverType)
	telemetry.Set("os", runtime.GOOS)
	telemetry.Set("arch", runtime.GOARCH)
	telemetry.Set("cpu", struct {
		BrandName  string `json:"brand_name,omitempty"`
		NumLogical int    `json:"num_logical,omitempty"`
		AESNI      bool   `json:"aes_ni,omitempty"`
	}{
		BrandName:  cpuid.CPU.BrandName,
		NumLogical: runtime.NumCPU(),
		AESNI:      cpuid.CPU.AesNi(),
	})
	if containerized := detectContainer(); containerized {
		telemetry.Set("container", containerized)
	}
	telemetry.StartEmitting()

	// Twiddle your thumbs
	instance.Wait()
}

// mustLogFatalf wraps log.Fatalf() in a way that ensures the
// output is always printed to stderr so the user can see it
// if the user is still there, even if the process log was not
// enabled. If this process is an upgrade, however, and the user
// might not be there anymore, this just logs to the process
// log and exits.
func mustLogFatalf(format string, args ...interface{}) {
	if !caddy.IsUpgrade() {
		log.SetOutput(os.Stderr)
	}
	log.Fatalf(format, args...)
}

// confLoader loads the Caddyfile using the -conf flag.
func confLoader(serverType string) (caddy.Input, error) {
	if conf == "" {
		return nil, nil
	}

	if conf == "stdin" {
		return caddy.CaddyfileFromPipe(os.Stdin, serverType)
	}

	var contents []byte
	if strings.Contains(conf, "*") {
		// Let caddyfile.doImport logic handle the globbed path
		contents = []byte("import " + conf)
	} else {
		var err error
		contents, err = ioutil.ReadFile(conf)
		if err != nil {
			return nil, err
		}
	}

	return caddy.CaddyfileInput{
		Contents:       contents,
		Filepath:       conf,
		ServerTypeName: serverType,
	}, nil
}

// defaultLoader loads the Caddyfile from the current working directory.
func defaultLoader(serverType string) (caddy.Input, error) {
	contents, err := ioutil.ReadFile(caddy.DefaultConfigFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return caddy.CaddyfileInput{
		Contents:       contents,
		Filepath:       caddy.DefaultConfigFile,
		ServerTypeName: serverType,
	}, nil
}

// setVersion figures out the version information
// based on variables set by -ldflags.
func setVersion() {
	// A development build is one that's not at a tag or has uncommitted changes
	devBuild = gitTag == "" || gitShortStat != ""

	if buildDate != "" {
		buildDate = " " + buildDate
	}

	// Only set the appVersion if -ldflags was used
	if gitNearestTag != "" || gitTag != "" {
		if devBuild && gitNearestTag != "" {
			appVersion = fmt.Sprintf("%s (+%s%s)",
				strings.TrimPrefix(gitNearestTag, "v"), gitCommit, buildDate)
		} else if gitTag != "" {
			appVersion = strings.TrimPrefix(gitTag, "v")
		}
	}
}

// setCPU parses string cpu and sets GOMAXPROCS
// according to its value. It accepts either
// a number (e.g. 3) or a percent (e.g. 50%).
// If the percent resolves to less than a single
// GOMAXPROCS, it rounds it up to GOMAXPROCS=1.
func setCPU(cpu string) error {
	var numCPU int

	availCPU := runtime.NumCPU()

	if strings.HasSuffix(cpu, "%") {
		// Percent
		var percent float32
		pctStr := cpu[:len(cpu)-1]
		pctInt, err := strconv.Atoi(pctStr)
		if err != nil || pctInt < 1 || pctInt > 100 {
			return errors.New("invalid CPU value: percentage must be between 1-100")
		}
		percent = float32(pctInt) / 100
		numCPU = int(float32(availCPU) * percent)
		if numCPU < 1 {
			numCPU = 1
		}
	} else {
		// Number
		num, err := strconv.Atoi(cpu)
		if err != nil || num < 1 {
			return errors.New("invalid CPU value: provide a number or percent greater than 0")
		}
		numCPU = num
	}

	if numCPU > availCPU {
		numCPU = availCPU
	}

	runtime.GOMAXPROCS(numCPU)
	return nil
}

// detectContainer attempts to determine whether the process is
// being run inside a container. References:
// https://tuhrig.de/how-to-know-you-are-inside-a-docker-container/
// https://stackoverflow.com/a/20012536/1048862
// https://gist.github.com/anantkamath/623ce7f5432680749e087cf8cfba9b69
func detectContainer() bool {
	if runtime.GOOS != "linux" {
		return false
	}

	file, err := os.Open("/proc/1/cgroup")
	if err != nil {
		return false
	}
	defer file.Close()

	i := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		i++
		if i > 1000 {
			return false
		}

		line := scanner.Text()
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}

		if strings.Contains(parts[2], "docker") ||
			strings.Contains(parts[2], "lxc") ||
			strings.Contains(parts[2], "moby") {
			return true
		}
	}

	return false
}

// initTelemetry initializes the telemetry engine.
func initTelemetry() error {
	uuidFilename := filepath.Join(caddy.AssetsPath(), "uuid")
	if customUUIDFile := os.Getenv("CADDY_UUID_FILE"); customUUIDFile != "" {
		uuidFilename = customUUIDFile
	}

	newUUID := func() uuid.UUID {
		id := uuid.New()
		err := os.MkdirAll(caddy.AssetsPath(), 0700)
		if err != nil {
			log.Printf("[ERROR] Persisting instance UUID: %v", err)
			return id
		}
		err = ioutil.WriteFile(uuidFilename, []byte(id.String()), 0600) // human-readable as a string
		if err != nil {
			log.Printf("[ERROR] Persisting instance UUID: %v", err)
		}
		return id
	}

	var id uuid.UUID

	// load UUID from storage, or create one if we don't have one
	if uuidFile, err := os.Open(uuidFilename); os.IsNotExist(err) {
		// no UUID exists yet; create a new one and persist it
		id = newUUID()
	} else if err != nil {
		log.Printf("[ERROR] Loading persistent UUID: %v", err)
		id = newUUID()
	} else {
		defer uuidFile.Close()
		uuidBytes, err := ioutil.ReadAll(uuidFile)
		if err != nil {
			log.Printf("[ERROR] Reading persistent UUID: %v", err)
			id = newUUID()
		} else {
			id, err = uuid.ParseBytes(uuidBytes)
			if err != nil {
				log.Printf("[ERROR] Parsing UUID: %v", err)
				id = newUUID()
			}
		}
	}

	// parse and check the list of disabled metrics
	var disabledMetricsSlice []string
	if len(disabledMetrics) > 0 {
		if len(disabledMetrics) > 1024 {
			// mitigate disk space exhaustion at the collection endpoint
			return fmt.Errorf("too many metrics to disable")
		}
		disabledMetricsSlice = strings.Split(disabledMetrics, ",")
		for i, metric := range disabledMetricsSlice {
			if metric == "instance_id" || metric == "timestamp" || metric == "disabled_metrics" {
				return fmt.Errorf("instance_id, timestamp, and disabled_metrics cannot be disabled")
			}
			if metric == "" {
				disabledMetricsSlice = append(disabledMetricsSlice[:i], disabledMetricsSlice[i+1:]...)
			}
		}
	}

	// initialize telemetry
	telemetry.Init(id, disabledMetricsSlice)

	// if any metrics were disabled, report which ones (so we know how representative the data is)
	if len(disabledMetricsSlice) > 0 {
		telemetry.Set("disabled_metrics", disabledMetricsSlice)
		log.Printf("[NOTICE] The following telemetry metrics are disabled: %s", disabledMetrics)
	}

	return nil
}

// LoadEnvFromFile loads additional envs if file provided and exists
// Envs in file should be in KEY=VALUE format
func LoadEnvFromFile(envFile string) error {
	if envFile == "" {
		return nil
	}

	file, err := os.Open(envFile)
	if err != nil {
		return err
	}
	defer file.Close()

	envMap, err := ParseEnvFile(file)
	if err != nil {
		return err
	}

	for k, v := range envMap {
		if err := os.Setenv(k, v); err != nil {
			return err
		}
	}

	return nil
}

// ParseEnvFile implements parse logic for environment files
func ParseEnvFile(envInput io.Reader) (map[string]string, error) {
	envMap := make(map[string]string)

	scanner := bufio.NewScanner(envInput)
	var line string
	lineNumber := 0

	for scanner.Scan() {
		line = strings.TrimSpace(scanner.Text())
		lineNumber++

		// skip lines starting with comment
		if strings.HasPrefix(line, "#") {
			continue
		}

		// skip empty line
		if len(line) == 0 {
			continue
		}

		fields := strings.SplitN(line, "=", 2)
		if len(fields) != 2 {
			return nil, fmt.Errorf("Can't parse line %d; line should be in KEY=VALUE format", lineNumber)
		}

		if strings.Contains(fields[0], " ") {
			return nil, fmt.Errorf("Can't parse line %d; KEY contains whitespace", lineNumber)
		}

		key := fields[0]
		val := fields[1]

		if key == "" {
			return nil, fmt.Errorf("Can't parse line %d; KEY can't be empty string", lineNumber)
		}
		envMap[key] = val
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return envMap, nil
}

const appName = "Caddy"

// Flags that control program flow or startup
var (
	serverType      string
	conf            string
	cpu             string
	envFile         string
	logfile         string
	revoke          string
	version         bool
	plugins         bool
	validate        bool
	disabledMetrics string
)

// Build information obtained with the help of -ldflags
var (
	appVersion = "(untracked dev build)" // inferred at startup
	devBuild   = true                    // inferred at startup

	buildDate        string // date -u
	gitTag           string // git describe --exact-match HEAD 2> /dev/null
	gitNearestTag    string // git describe --abbrev=0 --tags HEAD
	gitCommit        string // git rev-parse HEAD
	gitShortStat     string // git diff-index --shortstat
	gitFilesModified string // git diff-index --name-only HEAD
)

// This variable defines whether telemetry is enabled in Run.
var EnableTelemetry = true
