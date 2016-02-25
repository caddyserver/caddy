package main

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/kardianos/service"
	"github.com/mholt/caddy/caddy"
	"github.com/mholt/caddy/caddy/https"
	"github.com/xenolf/lego/acme"
	"gopkg.in/natefinch/lumberjack.v2"
)

var (
	conf    string
	cpu     string
	logfile string
	revoke  string
	version bool
	srvctl  string
)

const (
	appName    = "Caddy"
	appVersion = "0.8.1"
)

func init() {
	caddy.TrapSignals()
	flag.BoolVar(&https.Agreed, "agree", false, "Agree to Let's Encrypt Subscriber Agreement")
	flag.StringVar(&https.CAUrl, "ca", "https://acme-v01.api.letsencrypt.org/directory", "Certificate authority ACME server")
	flag.StringVar(&conf, "conf", "", "Configuration file to use (default="+caddy.DefaultConfigFile+")")
	flag.StringVar(&cpu, "cpu", "100%", "CPU cap")
	flag.StringVar(&https.DefaultEmail, "email", "", "Default Let's Encrypt account email address")
	flag.DurationVar(&caddy.GracefulTimeout, "grace", 5*time.Second, "Maximum duration of graceful shutdown")
	flag.StringVar(&caddy.Host, "host", caddy.DefaultHost, "Default host")
	flag.BoolVar(&caddy.HTTP2, "http2", true, "HTTP/2 support")
	flag.StringVar(&logfile, "log", "", "Process log file")
	flag.StringVar(&caddy.PidFile, "pidfile", "", "Path to write pid file")
	flag.StringVar(&caddy.Port, "port", caddy.DefaultPort, "Default port")
	flag.BoolVar(&caddy.Quiet, "quiet", false, "Quiet mode (no initialization output)")
	flag.StringVar(&revoke, "revoke", "", "Hostname for which to revoke the certificate")
	flag.StringVar(&caddy.Root, "root", caddy.DefaultRoot, "Root path to default site")
	flag.BoolVar(&version, "version", false, "Show version")
	flag.StringVar(&srvctl, "service", "", "Control a system service of Caddy")
}

func main() {
	flag.Parse() // called here in main() to allow other packages to set flags in their inits

	const svcPIDFile = `/run/Caddy.pid`

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
		fmt.Printf("%s %s\n", caddy.AppName, caddy.AppVersion)
		os.Exit(0)
	}

	// Create an absolute path to the caddy file for use
	// in a service.
	serviceCaddyPath := caddy.DefaultConfigFile
	if len(conf) != 0 {
		serviceCaddyPath = conf
	}
	if !filepath.IsAbs(serviceCaddyPath) {
		wd, err := os.Getwd()
		if err != nil {
			mustLogFatal(err)
		}
		serviceCaddyPath = filepath.Join(wd, serviceCaddyPath)
	}
	sys, err := service.New(app{}, &service.Config{
		Name:        caddy.AppName,
		DisplayName: caddy.AppName,

		Arguments: []string{"-conf", serviceCaddyPath, "-pidfile", svcPIDFile},

		Option: service.KeyValue{
			"RunWait":      caddy.Wait,
			"ReloadSignal": "USR1",
			"PIDFile":      svcPIDFile,
		},
	})
	if err != nil {
		mustLogFatal(err)
	}

	// Handle any service control commands.
	if len(srvctl) != 0 {
		err = service.Control(sys, srvctl)
		if err != nil {
			mustLogFatal(err, service.ControlAction)
		}
		return
	}

	err = sys.Run()
	if err != nil {
		mustLogFatal(err)
	}
}

type app struct{}

func (app) Start(s service.Service) error {
	if !service.Interactive() && len(conf) != 0 {
		// Set the WD here if running under a service.
		// This is required as on windows there is no way to set the current working
		// directory as a service.
		dir, _ := filepath.Split(conf)
		err := os.Chdir(dir)
		if err != nil {
			return err
		}
	}
	// Set CPU cap
	err := setCPU(cpu)
	if err != nil {
		return err
	}

	// Get Caddyfile input
	caddyfile, err := caddy.LoadCaddyfile(loadCaddyfile)
	if err != nil {
		return err
	}

	// Start your engines
	return caddy.Start(caddyfile)
}
func (app) Stop(s service.Service) error {
	return caddy.Stop()
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
