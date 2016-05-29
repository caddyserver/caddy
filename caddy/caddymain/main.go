package caddymain

import (
	"flag"
	"io/ioutil"
	"log"
	"os"

	"github.com/mholt/caddy2"

	// plug in the HTTP server type
	_ "github.com/mholt/caddy2/caddyhttp"
	"github.com/mholt/caddy2/caddytls"

	// TODO: The build server will put the rest of the plugins to
	// import here. Each server imports their default plugins
	// because they're hard-coded as imports.
)

func init() {
	caddy.TrapSignals()

	flag.BoolVar(&caddytls.Agreed, "agree", false, "Agree to the CA's Subscriber Agreement")
	// TODO: Change from staging to v01
	flag.StringVar(&caddytls.CAUrl, "ca", "https://acme-staging.api.letsencrypt.org/directory", "URL to certificate authority's ACME server directory")
	flag.StringVar(&conf, "conf", "", "Caddyfile to load (default \""+caddy.DefaultConfigFile+"\")")
	flag.StringVar(&caddytls.DefaultEmail, "email", "", "Default ACME CA account email address")
	flag.StringVar(&serverType, "type", "http", "Type of server to run")

	caddy.RegisterCaddyfileLoader("flag", caddy.LoaderFunc(confLoader))
	caddy.SetDefaultCaddyfileLoader("default", caddy.LoaderFunc(defaultLoader))
}

// Run is Caddy's main() function.
func Run() {
	flag.Parse()

	// Get Caddyfile input
	caddyfile, err := caddy.LoadCaddyfile(serverType)
	if err != nil {
		mustLogFatal(err)
	}

	// Start your engines
	instance, err := caddy.Start(caddyfile)
	if err != nil {
		mustLogFatal(err)
	}

	// Twiddle your thumbs
	instance.Wait()
}

// mustLogFatal wraps log.Fatal() in a way that ensures the
// output is always printed to stderr so the user can see it
// if the user is still there, even if the process log was not
// enabled. If this process is a restart, however, and the user
// might not be there anymore, this just logs to the process
// log and exits.
func mustLogFatal(args ...interface{}) {
	if !caddy.IsRestart() {
		log.SetOutput(os.Stderr)
	}
	log.Fatal(args...)
}

// confLoader loads the Caddyfile using the -conf flag.
func confLoader(serverType string) (caddy.Input, error) {
	if conf == "" {
		return nil, nil
	}

	if conf == "stdin" {
		return caddy.CaddyfileFromPipe(os.Stdin)
	}

	contents, err := ioutil.ReadFile(conf)
	if err != nil {
		return nil, err
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

var (
	serverType string
	conf       string
)
