// Copyright 2015 Matthew Holt and The Caddy Authors
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

package caddycmd

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

func init() {
	// set a fitting User-Agent for ACME requests
	goModule := caddy.GoModule()
	cleanModVersion := strings.TrimPrefix(goModule.Version, "v")
	certmagic.UserAgent = "Caddy/" + cleanModVersion

	// by using Caddy, user indicates agreement to CA terms
	// (very important, or ACME account creation will fail!)
	certmagic.DefaultACME.Agreed = true
}

// Main implements the main function of the caddy command.
// Call this if Caddy is to be the main() of your program.
func Main() {
	switch len(os.Args) {
	case 0:
		fmt.Printf("[FATAL] no arguments provided by OS; args[0] must be command\n")
		os.Exit(caddy.ExitCodeFailedStartup)
	case 1:
		os.Args = append(os.Args, "help")
	}

	subcommandName := os.Args[1]
	subcommand, ok := commands[subcommandName]
	if !ok {
		if strings.HasPrefix(os.Args[1], "-") {
			// user probably forgot to type the subcommand
			fmt.Println("[ERROR] first argument must be a subcommand; see 'caddy help'")
		} else {
			fmt.Printf("[ERROR] '%s' is not a recognized subcommand; see 'caddy help'\n", os.Args[1])
		}
		os.Exit(caddy.ExitCodeFailedStartup)
	}

	fs := subcommand.Flags
	if fs == nil {
		fs = flag.NewFlagSet(subcommand.Name, flag.ExitOnError)
	}

	err := fs.Parse(os.Args[2:])
	if err != nil {
		fmt.Println(err)
		os.Exit(caddy.ExitCodeFailedStartup)
	}

	exitCode, err := subcommand.Func(Flags{fs})
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", subcommand.Name, err)
	}
	if err := cleanup(); err != nil {
		fmt.Fprintf(os.Stderr, "error restoring console to functional state: %v\n", err)
	}
	os.Exit(exitCode)
}

// handlePingbackConn reads from conn and ensures it matches
// the bytes in expect, or returns an error if it doesn't.
func handlePingbackConn(conn net.Conn, expect []byte) error {
	defer conn.Close()
	confirmationBytes, err := io.ReadAll(io.LimitReader(conn, 32))
	if err != nil {
		return err
	}
	if !bytes.Equal(confirmationBytes, expect) {
		return fmt.Errorf("wrong confirmation: %x", confirmationBytes)
	}
	return nil
}

// loadConfig loads the config from configFile and adapts it
// using adapterName. If adapterName is specified, configFile
// must be also. If no configFile is specified, it tries
// loading a default config file. The lack of a config file is
// not treated as an error, but false will be returned if
// there is no config available. It prints any warnings to stderr,
// and returns the resulting JSON config bytes along with
// whether a config file was loaded or not.
func loadConfig(configFile, adapterName string) ([]byte, string, error) {
	// specifying an adapter without a config file is ambiguous
	if adapterName != "" && configFile == "" {
		return nil, "", fmt.Errorf("cannot adapt config without config file (use --config)")
	}

	// load initial config and adapter
	var config []byte
	var cfgAdapter caddyconfig.Adapter
	var err error
	if configFile != "" {
		if configFile == "-" {
			config, err = io.ReadAll(os.Stdin)
		} else {
			config, err = os.ReadFile(configFile)
		}
		if err != nil {
			return nil, "", fmt.Errorf("reading config file: %v", err)
		}
		caddy.Log().Info("using provided configuration",
			zap.String("config_file", configFile),
			zap.String("config_adapter", adapterName))
	} else if adapterName == "" {
		// as a special case when no config file or adapter
		// is specified, see if the Caddyfile adapter is
		// plugged in, and if so, try using a default Caddyfile
		cfgAdapter = caddyconfig.GetAdapter("caddyfile")
		if cfgAdapter != nil {
			config, err = os.ReadFile("Caddyfile")
			if os.IsNotExist(err) {
				// okay, no default Caddyfile; pretend like this never happened
				cfgAdapter = nil
			} else if err != nil {
				// default Caddyfile exists, but error reading it
				return nil, "", fmt.Errorf("reading default Caddyfile: %v", err)
			} else {
				// success reading default Caddyfile
				configFile = "Caddyfile"
				caddy.Log().Info("using adjacent Caddyfile")
			}
		}
	}

	// as a special case, if a config file called "Caddyfile" was
	// specified, and no adapter is specified, assume caddyfile adapter
	// for convenience
	if strings.HasPrefix(filepath.Base(configFile), "Caddyfile") &&
		filepath.Ext(configFile) != ".json" &&
		adapterName == "" {
		adapterName = "caddyfile"
	}

	// load config adapter
	if adapterName != "" {
		cfgAdapter = caddyconfig.GetAdapter(adapterName)
		if cfgAdapter == nil {
			return nil, "", fmt.Errorf("unrecognized config adapter: %s", adapterName)
		}
	}

	// adapt config
	if cfgAdapter != nil {
		adaptedConfig, warnings, err := cfgAdapter.Adapt(config, map[string]interface{}{
			"filename": configFile,
		})
		if err != nil {
			return nil, "", fmt.Errorf("adapting config using %s: %v", adapterName, err)
		}
		for _, warn := range warnings {
			msg := warn.Message
			if warn.Directive != "" {
				msg = fmt.Sprintf("%s: %s", warn.Directive, warn.Message)
			}
			caddy.Log().Warn(msg, zap.String("adapter", adapterName), zap.String("file", warn.File), zap.Int("line", warn.Line))
		}
		config = adaptedConfig
	}

	return config, configFile, nil
}

// watchConfigFile watches the config file at filename for changes
// and reloads the config if the file was updated. This function
// blocks indefinitely; it only quits if the poller has errors for
// long enough time. The filename passed in must be the actual
// config file used, not one to be discovered.
func watchConfigFile(filename, adapterName string) {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("[PANIC] watching config file: %v\n%s", err, debug.Stack())
		}
	}()

	// make our logger; since config reloads can change the
	// default logger, we need to get it dynamically each time
	logger := func() *zap.Logger {
		return caddy.Log().
			Named("watcher").
			With(zap.String("config_file", filename))
	}

	// get the initial timestamp on the config file
	info, err := os.Stat(filename)
	if err != nil {
		logger().Error("cannot watch config file", zap.Error(err))
		return
	}
	lastModified := info.ModTime()

	logger().Info("watching config file for changes")

	// if the file disappears or something, we can
	// stop polling if the error lasts long enough
	var lastErr time.Time
	finalError := func(err error) bool {
		if lastErr.IsZero() {
			lastErr = time.Now()
			return false
		}
		if time.Since(lastErr) > 30*time.Second {
			logger().Error("giving up watching config file; too many errors",
				zap.Error(err))
			return true
		}
		return false
	}

	// begin poller
	//nolint:staticcheck
	for range time.Tick(1 * time.Second) {
		// get the file info
		info, err := os.Stat(filename)
		if err != nil {
			if finalError(err) {
				return
			}
			continue
		}
		lastErr = time.Time{} // no error, so clear any memory of one

		// if it hasn't changed, nothing to do
		if !info.ModTime().After(lastModified) {
			continue
		}

		logger().Info("config file changed; reloading")

		// remember this timestamp
		lastModified = info.ModTime()

		// load the contents of the file
		config, _, err := loadConfig(filename, adapterName)
		if err != nil {
			logger().Error("unable to load latest config", zap.Error(err))
			continue
		}

		// apply the updated config
		err = caddy.Load(config, false)
		if err != nil {
			logger().Error("applying latest config", zap.Error(err))
			continue
		}
	}
}

// Flags wraps a FlagSet so that typed values
// from flags can be easily retrieved.
type Flags struct {
	*flag.FlagSet
}

// String returns the string representation of the
// flag given by name. It panics if the flag is not
// in the flag set.
func (f Flags) String(name string) string {
	return f.FlagSet.Lookup(name).Value.String()
}

// Bool returns the boolean representation of the
// flag given by name. It returns false if the flag
// is not a boolean type. It panics if the flag is
// not in the flag set.
func (f Flags) Bool(name string) bool {
	val, _ := strconv.ParseBool(f.String(name))
	return val
}

// Int returns the integer representation of the
// flag given by name. It returns 0 if the flag
// is not an integer type. It panics if the flag is
// not in the flag set.
func (f Flags) Int(name string) int {
	val, _ := strconv.ParseInt(f.String(name), 0, strconv.IntSize)
	return int(val)
}

// Float64 returns the float64 representation of the
// flag given by name. It returns false if the flag
// is not a float64 type. It panics if the flag is
// not in the flag set.
func (f Flags) Float64(name string) float64 {
	val, _ := strconv.ParseFloat(f.String(name), 64)
	return val
}

// Duration returns the duration representation of the
// flag given by name. It returns false if the flag
// is not a duration type. It panics if the flag is
// not in the flag set.
func (f Flags) Duration(name string) time.Duration {
	val, _ := caddy.ParseDuration(f.String(name))
	return val
}

// flagHelp returns the help text for fs.
func flagHelp(fs *flag.FlagSet) string {
	if fs == nil {
		return ""
	}

	// temporarily redirect output
	out := fs.Output()
	defer fs.SetOutput(out)

	buf := new(bytes.Buffer)
	fs.SetOutput(buf)
	fs.PrintDefaults()
	return buf.String()
}

func loadEnvFromFile(envFile string) error {
	file, err := os.Open(envFile)
	if err != nil {
		return fmt.Errorf("reading environment file: %v", err)
	}
	defer file.Close()

	envMap, err := parseEnvFile(file)
	if err != nil {
		return fmt.Errorf("parsing environment file: %v", err)
	}

	for k, v := range envMap {
		if err := os.Setenv(k, v); err != nil {
			return fmt.Errorf("setting environment variables: %v", err)
		}
	}

	// Update the storage paths to ensure they have the proper
	// value after loading a specified env file.
	caddy.ConfigAutosavePath = filepath.Join(caddy.AppConfigDir(), "autosave.json")
	caddy.DefaultStorage = &certmagic.FileStorage{Path: caddy.AppDataDir()}

	return nil
}

func parseEnvFile(envInput io.Reader) (map[string]string, error) {
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
			return nil, fmt.Errorf("can't parse line %d; line should be in KEY=VALUE format", lineNumber)
		}

		if strings.Contains(fields[0], " ") {
			return nil, fmt.Errorf("bad key on line %d: contains whitespace", lineNumber)
		}

		key := fields[0]
		val := fields[1]

		if key == "" {
			return nil, fmt.Errorf("missing or empty key on line %d", lineNumber)
		}
		envMap[key] = val
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return envMap, nil
}

func printEnvironment() {
	fmt.Printf("caddy.HomeDir=%s\n", caddy.HomeDir())
	fmt.Printf("caddy.AppDataDir=%s\n", caddy.AppDataDir())
	fmt.Printf("caddy.AppConfigDir=%s\n", caddy.AppConfigDir())
	fmt.Printf("caddy.ConfigAutosavePath=%s\n", caddy.ConfigAutosavePath)
	fmt.Printf("caddy.Version=%s\n", CaddyVersion())
	fmt.Printf("runtime.GOOS=%s\n", runtime.GOOS)
	fmt.Printf("runtime.GOARCH=%s\n", runtime.GOARCH)
	fmt.Printf("runtime.Compiler=%s\n", runtime.Compiler)
	fmt.Printf("runtime.NumCPU=%d\n", runtime.NumCPU())
	fmt.Printf("runtime.GOMAXPROCS=%d\n", runtime.GOMAXPROCS(0))
	fmt.Printf("runtime.Version=%s\n", runtime.Version())
	cwd, err := os.Getwd()
	if err != nil {
		cwd = fmt.Sprintf("<error: %v>", err)
	}
	fmt.Printf("os.Getwd=%s\n\n", cwd)
	for _, v := range os.Environ() {
		fmt.Println(v)
	}
}

// CaddyVersion returns a detailed version string, if available.
func CaddyVersion() string {
	goModule := caddy.GoModule()
	ver := goModule.Version
	if goModule.Sum != "" {
		ver += " " + goModule.Sum
	}
	if goModule.Replace != nil {
		ver += " => " + goModule.Replace.Path
		if goModule.Replace.Version != "" {
			ver += "@" + goModule.Replace.Version
		}
		if goModule.Replace.Sum != "" {
			ver += " " + goModule.Replace.Sum
		}
	}
	return ver
}
