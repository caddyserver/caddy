package caddy

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

	"github.com/mholt/caddy/caddy/letsencrypt"
	"github.com/xenolf/lego/acme"
)

var (
	conf    string
	cpu     string
	logfile string
	revoke  string
	version bool
)

const (
	appName    = "Caddy"
	appVersion = "0.8.1"
)

// Main runs all of the logic that the caddy executable runs, including flag parsing, configuration loading,
// and starting the server. This should never return until the server shuts down.
func Main() {
	TrapSignals()
	flag.BoolVar(&letsencrypt.Agreed, "agree", false, "Agree to Let's Encrypt Subscriber Agreement")
	flag.StringVar(&letsencrypt.CAUrl, "ca", "https://acme-v01.api.letsencrypt.org/directory", "Certificate authority ACME server")
	flag.StringVar(&conf, "conf", "", "Configuration file to use (default="+DefaultConfigFile+")")
	flag.StringVar(&cpu, "cpu", "100%", "CPU cap")
	flag.StringVar(&letsencrypt.DefaultEmail, "email", "", "Default Let's Encrypt account email address")
	flag.DurationVar(&GracefulTimeout, "grace", 5*time.Second, "Maximum duration of graceful shutdown")
	flag.StringVar(&Host, "host", DefaultHost, "Default host")
	flag.BoolVar(&HTTP2, "http2", true, "HTTP/2 support") // TODO: temporary flag until http2 merged into std lib
	flag.StringVar(&logfile, "log", "", "Process log file")
	flag.StringVar(&PidFile, "pidfile", "", "Path to write pid file")
	flag.StringVar(&Port, "port", DefaultPort, "Default port")
	flag.BoolVar(&Quiet, "quiet", false, "Quiet mode (no initialization output)")
	flag.StringVar(&revoke, "revoke", "", "Hostname for which to revoke the certificate")
	flag.StringVar(&Root, "root", DefaultRoot, "Root path to default site")
	flag.BoolVar(&version, "version", false, "Show version")

	flag.Parse() // called here in main() to allow other packages to set flags in their inits

	AppName = appName
	AppVersion = appVersion
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
		file, err := os.OpenFile(logfile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("Error opening process log file: %v", err)
		}
		log.SetOutput(file)
	}

	if revoke != "" {
		err := letsencrypt.Revoke(revoke)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Revoked certificate for %s\n", revoke)
		os.Exit(0)
	}
	if version {
		fmt.Printf("%s %s\n", AppName, AppVersion)
		os.Exit(0)
	}

	// Set CPU cap
	err := setCPU(cpu)
	if err != nil {
		mustLogFatal(err)
	}

	// Get Caddyfile input
	caddyfile, err := LoadCaddyfile(loadCaddyfile)
	if err != nil {
		mustLogFatal(err)
	}

	// Start your engines
	err = Start(caddyfile)
	if err != nil {
		mustLogFatal(err)
	}

	// Twiddle your thumbs
	Wait()
}

// mustLogFatal just wraps log.Fatal() in a way that ensures the
// output is always printed to stderr so the user can see it
// if the user is still there, even if the process log was not
// enabled. If this process is a restart, however, and the user
// might not be there anymore, this just logs to the process log
// and exits.
func mustLogFatal(args ...interface{}) {
	if !IsRestart() {
		log.SetOutput(os.Stderr)
	}
	log.Fatal(args...)
}

func loadCaddyfile() (Input, error) {
	// Try -conf flag
	if conf != "" {
		if conf == "stdin" {
			return CaddyfileFromPipe(os.Stdin)
		}

		contents, err := ioutil.ReadFile(conf)
		if err != nil {
			return nil, err
		}

		return CaddyfileInput{
			Contents: contents,
			Filepath: conf,
			RealFile: true,
		}, nil
	}

	// command line args
	if flag.NArg() > 0 {
		confBody := Host + ":" + Port + "\n" + strings.Join(flag.Args(), "\n")
		return CaddyfileInput{
			Contents: []byte(confBody),
			Filepath: "args",
		}, nil
	}

	// Caddyfile in cwd
	contents, err := ioutil.ReadFile(DefaultConfigFile)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultInput(), nil
		}
		return nil, err
	}
	return CaddyfileInput{
		Contents: contents,
		Filepath: DefaultConfigFile,
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
