package main

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/mholt/caddy/caddy"
	"github.com/mholt/caddy/caddy/https"
	"github.com/xenolf/lego/acme"
	"gopkg.in/natefinch/lumberjack.v2"
)

func init() {
	caddy.TrapSignals()
	setVersion()
	flag.BoolVar(&https.Agreed, "agree", false, "Agree to Let's Encrypt Subscriber Agreement")
	flag.StringVar(&https.CAUrl, "ca", "https://acme-v01.api.letsencrypt.org/directory", "Certificate authority ACME server")
	flag.StringVar(&conf, "conf", "", "Configuration file to use (default="+caddy.DefaultConfigFile+")")
	flag.StringVar(&cpu, "cpu", "100%", "CPU cap")
	flag.StringVar(&https.DefaultEmail, "email", "", "Default Let's Encrypt account email address")
	flag.DurationVar(&caddy.GracefulTimeout, "grace", 5*time.Second, "Maximum duration of graceful shutdown")
	flag.StringVar(&caddy.Host, "host", caddy.DefaultHost, "Default host")
	flag.BoolVar(&caddy.HTTP2, "http2", true, "Use HTTP/2")
	flag.StringVar(&logfile, "log", "", "Process log file")
	flag.StringVar(&caddy.PidFile, "pidfile", "", "Path to write pid file")
	flag.StringVar(&caddy.Port, "port", caddy.DefaultPort, "Default port")
	flag.BoolVar(&caddy.Quiet, "quiet", false, "Quiet mode (no initialization output)")
	flag.StringVar(&caddy.RestartMode, "restart", "", "Restart mode (inproc for in process restart)")
	flag.StringVar(&revoke, "revoke", "", "Hostname for which to revoke the certificate")
	flag.StringVar(&caddy.Root, "root", caddy.DefaultRoot, "Root path to default site")
	flag.BoolVar(&version, "version", false, "Show version")
	flag.BoolVar(&directives, "directives", false, "List supported directives")
}

func main() {
	flag.Parse() // called here in main() to allow other packages to set flags in their inits

	caddy.AppName = appName
	caddy.AppVersion = appVersion
	acme.UserAgent = appName + "/" + appVersion

	// set up process log before anything bad happens
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

	if revoke != "" {
		err := https.Revoke(revoke)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Revoked certificate for %s\n", revoke)
		os.Exit(0)
	}
	if version {
		fmt.Printf("%s %s\n", appName, appVersion)
		if devBuild && gitShortStat != "" {
			fmt.Printf("%s\n%s\n", gitShortStat, gitFilesModified)
		}
		os.Exit(0)
	}
	if directives {
		for _, d := range caddy.Directives() {
			fmt.Println(d)
		}
		os.Exit(0)
	}

	// Set CPU cap
	err := setCPU(cpu)
	if err != nil {
		mustLogFatal(err)
	}

	// Get Caddyfile input
	caddyfile, err := caddy.LoadCaddyfile(loadCaddyfile)
	if err != nil {
		mustLogFatal(err)
	}

	// Start your engines
	err = caddy.Start(caddyfile)
	if err != nil {
		mustLogFatal(err)
	}

	// Twiddle your thumbs
	caddy.Wait()
}

// mustLogFatal just wraps log.Fatal() in a way that ensures the
// output is always printed to stderr so the user can see it
// if the user is still there, even if the process log was not
// enabled. If this process is a restart, however, and the user
// might not be there anymore, this just logs to the process log
// and exits.
func mustLogFatal(args ...interface{}) {
	if !caddy.IsRestart() {
		log.SetOutput(os.Stderr)
	}
	log.Fatal(args...)
}

func loadCaddyfile() (caddy.Input, error) {
	// Try -conf flag
	if conf != "" {
		if conf == "stdin" {
			return caddy.CaddyfileFromPipe(os.Stdin)
		}

		contents, err := ioutil.ReadFile(conf)
		if err != nil {
			return nil, err
		}

		return caddy.CaddyfileInput{
			Contents: contents,
			Filepath: conf,
			RealFile: true,
		}, nil
	}

	// command line args
	if flag.NArg() > 0 {
		confBody := caddy.Host + ":" + caddy.Port + "\n" + strings.Join(flag.Args(), "\n")
		return caddy.CaddyfileInput{
			Contents: []byte(confBody),
			Filepath: "args",
		}, nil
	}

	// Caddyfile in cwd
	contents, err := ioutil.ReadFile(caddy.DefaultConfigFile)
	if err != nil {
		if os.IsNotExist(err) {
			return caddy.DefaultInput(), nil
		}
		return nil, err
	}
	return caddy.CaddyfileInput{
		Contents: contents,
		Filepath: caddy.DefaultConfigFile,
		RealFile: true,
	}, nil
}

// setCPU parses string cpu and sets GOMAXPROCS
// according to its value. It accepts either
// a number (e.g. 3) or a percent (e.g. 50%).
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

// setVersion figures out the version information based on
// variables set by -ldflags.
func setVersion() {
	// A development build is one that's not at a tag or has uncommitted changes
	devBuild = gitTag == "" || gitShortStat != ""

	// Only set the appVersion if -ldflags was used
	if gitNearestTag != "" || gitTag != "" {
		if devBuild && gitNearestTag != "" {
			appVersion = fmt.Sprintf("%s (+%s %s)",
				strings.TrimPrefix(gitNearestTag, "v"), gitCommit, buildDate)
		} else if gitTag != "" {
			appVersion = strings.TrimPrefix(gitTag, "v")
		}
	}
}

const appName = "Caddy"

// Flags that control program flow or startup
var (
	conf       string
	cpu        string
	logfile    string
	revoke     string
	version    bool
	directives bool
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
