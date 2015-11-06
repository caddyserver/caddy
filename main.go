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

	"github.com/mholt/caddy/caddy"
	"github.com/mholt/caddy/caddy/letsencrypt"
)

var (
	conf    string
	cpu     string
	version bool
	revoke  string
	logfile string
)

const (
	appName    = "Caddy"
	appVersion = "0.8 beta 2"
)

func init() {
	flag.StringVar(&conf, "conf", "", "Configuration file to use (default="+caddy.DefaultConfigFile+")")
	flag.BoolVar(&caddy.HTTP2, "http2", true, "HTTP/2 support") // TODO: temporary flag until http2 merged into std lib
	flag.BoolVar(&caddy.Quiet, "quiet", false, "Quiet mode (no initialization output)")
	flag.StringVar(&cpu, "cpu", "100%", "CPU cap")
	flag.StringVar(&caddy.Root, "root", caddy.DefaultRoot, "Root path to default site")
	flag.StringVar(&caddy.Host, "host", caddy.DefaultHost, "Default host")
	flag.StringVar(&caddy.Port, "port", caddy.DefaultPort, "Default port")
	flag.BoolVar(&version, "version", false, "Show version")
	// TODO: Boulder dev URL is: http://192.168.99.100:4000
	// TODO: Staging API URL is: https://acme-staging.api.letsencrypt.org
	// TODO: Production endpoint is: https://acme-v01.api.letsencrypt.org
	flag.StringVar(&letsencrypt.CAUrl, "ca", "https://acme-staging.api.letsencrypt.org", "Certificate authority ACME server")
	flag.BoolVar(&letsencrypt.Agreed, "agree", false, "Agree to Let's Encrypt Subscriber Agreement")
	flag.StringVar(&letsencrypt.DefaultEmail, "email", "", "Default Let's Encrypt account email address")
	flag.StringVar(&revoke, "revoke", "", "Hostname for which to revoke the certificate")
	flag.StringVar(&logfile, "log", "", "Process log file")
}

func main() {
	flag.Parse() // called here in main() to allow other packages to set flags in their inits

	caddy.AppName = appName
	caddy.AppVersion = appVersion

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
			log.Fatalf("Error opening log file: %v", err)
		}
		log.SetOutput(file)
	}

	if version {
		fmt.Printf("%s %s\n", caddy.AppName, caddy.AppVersion)
		os.Exit(0)
	}
	if revoke != "" {
		err := letsencrypt.Revoke(revoke)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Revoked certificate for %s\n", revoke)
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
		if caddy.IsRestart() {
			log.Printf("[ERROR] Upon starting %s: %v", appName, err)
		} else {
			mustLogFatal(err)
		}
	}

	// Twiddle your thumbs
	caddy.Wait()
}

// mustLogFatal just wraps log.Fatal() in a way that ensures the
// output is always printed to stderr so the user can see it,
// even if the process log was not enabled.
func mustLogFatal(args ...interface{}) {
	log.SetOutput(os.Stderr)
	log.Fatal(args...)
}

func loadCaddyfile() (caddy.Input, error) {
	// -conf flag
	if conf != "" {
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
		confBody := ":" + caddy.DefaultPort + "\n" + strings.Join(flag.Args(), "\n")
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
