package main

import (
	"flag"
	"io/ioutil"
	"log"
	"os"

	"github.com/mholt/caddy2"

	_ "github.com/mholt/caddy2/caddyhttp"
	"github.com/mholt/caddy2/shared/caddytls"
	// TODO: The build server will put the rest of the plugins to
	// import here. Each server imports their default plugins
	// because they're hard-coded as imports.
)

func init() {
	caddy.TrapSignals()

	flag.StringVar(&serverType, "type", "http", "Type of server to run")

	flag.StringVar(&defaultLoader.conf, "conf", "", "Caddyfile to load (default="+caddy.DefaultConfigFile+")")

	flag.BoolVar(&caddytls.Agreed, "agree", false, "Agree to the CA's Subscriber Agreement")
	// TODO: Change from staging to v01
	flag.StringVar(&caddytls.CAUrl, "ca", "https://acme-staging.api.letsencrypt.org/directory", "URL to certificate authority's ACME server directory")
	flag.StringVar(&caddytls.DefaultEmail, "email", "", "Default ACME CA account email address")

	caddy.AddCaddyfileLoader("main", defaultLoader)
}

func main() {
	flag.Parse()

	// Get Caddyfile input
	// TODO: Does this depend on server type... or...
	caddyfile, err := caddy.LoadCaddyfile()
	if err != nil {
		mustLogFatal(err)
	}

	// Start your engines
	err = caddy.Start(serverType, caddyfile)
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

var defaultLoader = new(caddyfileLoader)

type caddyfileLoader struct {
	conf   string
	isFile bool
}

func (dl *caddyfileLoader) Load() (caddy.Input, error) {
	// Try -conf flag
	if dl.conf != "" {
		if dl.conf == "stdin" {
			return caddy.CaddyfileFromPipe(os.Stdin)
		}

		contents, err := ioutil.ReadFile(dl.conf)
		if err != nil {
			return nil, err
		}

		dl.isFile = true
		return caddy.CaddyfileInput{
			Contents: contents,
			Filepath: dl.conf,
		}, nil
	}

	// command line args
	// TODO.
	// if flag.NArg() > 0 {
	// 	confBody := caddy.Host + ":" + caddy.Port + "\n" + strings.Join(flag.Args(), "\n")
	// 	return caddy.CaddyfileInput{
	// 		Contents: []byte(confBody),
	// 		Filepath: "args",
	// 	}, nil
	// }

	// Caddyfile in cwd
	contents, err := ioutil.ReadFile(caddy.DefaultConfigFile)
	if err != nil {
		if os.IsNotExist(err) {
			return caddy.DefaultInput(serverType), nil
		}
		return nil, err
	}
	dl.isFile = true
	return caddy.CaddyfileInput{
		Contents: contents,
		Filepath: caddy.DefaultConfigFile,
	}, nil
}

var (
	serverType string
	conf       string
)
