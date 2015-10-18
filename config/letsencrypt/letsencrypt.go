package letsencrypt

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/middleware/redirect"
	"github.com/mholt/caddy/server"
	"github.com/xenolf/lego/acme"
)

// Activate sets up TLS for each server config in configs
// as needed. It only skips the config if the cert and key
// are already provided or if plaintext http is explicitly
// specified as the port.
//
// This function may prompt the user to provide an email
// address if none is available through other means. It
// prefers the email address specified in the config, but
// if that is not available it will check the command line
// argument. If absent, it will use the most recent email
// address from last time. If there isn't one, the user
// will be prompted. If the user leaves email blank, <TODO>.
func Activate(configs []server.Config) ([]server.Config, error) {
	// Group configs by LE email address; this will help us
	// reduce round-trips when getting the certs.
	initMap, err := groupConfigsByEmail(configs)
	if err != nil {
		return configs, err
	}

	// Loop through each email address and obtain certs; we can obtain more
	// than one certificate per email address, and still save them individually.
	for leEmail, serverConfigs := range initMap {
		// make client to service this email address with CA server
		client, err := newClient(leEmail)
		if err != nil {
			return configs, err
		}

		// client is ready, so let's get free, trusted SSL certificates! yeah!
		certificates, err := obtainCertificates(client, serverConfigs)
		if err != nil {
			return configs, err
		}

		// ... that's it. save the certs, keys, and metadata files to disk
		err = saveCertsAndKeys(certificates)
		if err != nil {
			return configs, err
		}

		// it all comes down to this: filling in the file path of a valid certificate automatically
		configs = autoConfigure(configs, serverConfigs)
	}

	return configs, nil
}

// groupConfigsByEmail groups configs by the Let's Encrypt email address
// associated to them or to the default Let's Encrypt email address. If the
// default email is not available, the user will be prompted to provide one.
func groupConfigsByEmail(configs []server.Config) (map[string][]*server.Config, error) {
	initMap := make(map[string][]*server.Config)
	for i := 0; i < len(configs); i++ {
		if configs[i].TLS.Certificate == "" && configs[i].TLS.Key == "" && configs[i].Port != "http" { // TODO: && !cfg.Host.IsLoopback()
			leEmail := getEmail(configs[i])
			if leEmail == "" {
				return nil, errors.New("must have email address to serve HTTPS without existing certificate and key")
			}
			initMap[leEmail] = append(initMap[leEmail], &configs[i])
		}
	}
	return initMap, nil
}

// newClient creates a new ACME client to facilitate communication
// with the Let's Encrypt CA server on behalf of the user specified
// by leEmail. As part of this process, a user will be loaded from
// disk (if already exists) or created new and registered via ACME
// and saved to the file system for next time.
func newClient(leEmail string) (*acme.Client, error) {
	// Look up or create the LE user account
	leUser, err := getUser(leEmail)
	if err != nil {
		return nil, err
	}

	// The client facilitates our communication with the CA server.
	client := acme.NewClient(caURL, &leUser, rsaKeySize, exposePort, true) // TODO: Dev mode is enabled

	// If not registered, the user must register an account with the CA
	// and agree to terms
	if leUser.Registration == nil {
		reg, err := client.Register()
		if err != nil {
			return nil, errors.New("registration error: " + err.Error())
		}
		leUser.Registration = reg

		// TODO: we can just do the agreement once: when registering, right?
		err = client.AgreeToTos()
		if err != nil {
			saveUser(leUser) // TODO: Might as well try, right? Error check?
			return nil, errors.New("error agreeing to terms: " + err.Error())
		}

		// save user to the file system
		err = saveUser(leUser)
		if err != nil {
			return nil, errors.New("could not save user: " + err.Error())
		}
	}

	return client, nil
}

// obtainCertificates obtains certificates from the CA server for
// the configurations in serverConfigs using client.
func obtainCertificates(client *acme.Client, serverConfigs []*server.Config) ([]acme.CertificateResource, error) {
	// collect all the hostnames into one slice
	var hosts []string
	for _, cfg := range serverConfigs {
		hosts = append(hosts, cfg.Host)
	}

	certificates, err := client.ObtainCertificates(hosts)
	if err != nil {
		return nil, errors.New("error obtaining certs: " + err.Error())
	}

	return certificates, nil
}

// saveCertificates saves each certificate resource to disk. This
// includes the certificate file itself, the private key, and the
// metadata file.
func saveCertsAndKeys(certificates []acme.CertificateResource) error {
	for _, cert := range certificates {
		os.MkdirAll(storage.Site(cert.Domain), 0700)

		// Save cert
		err := ioutil.WriteFile(storage.SiteCertFile(cert.Domain), cert.Certificate, 0600)
		if err != nil {
			return err
		}

		// Save private key
		err = ioutil.WriteFile(storage.SiteKeyFile(cert.Domain), cert.PrivateKey, 0600)
		if err != nil {
			return err
		}

		// Save cert metadata
		jsonBytes, err := json.MarshalIndent(&CertificateMeta{URL: cert.CertURL, Domain: cert.Domain}, "", "\t")
		if err != nil {
			return err
		}
		err = ioutil.WriteFile(storage.SiteMetaFile(cert.Domain), jsonBytes, 0600)
		if err != nil {
			return err
		}
	}
	return nil
}

// autoConfigure enables TLS on all the configs in serverConfigs
// and appends, if necessary, new configs to allConfigs that redirect
// plaintext HTTP to their HTTPS counterparts.
func autoConfigure(allConfigs []server.Config, serverConfigs []*server.Config) []server.Config {
	for _, cfg := range serverConfigs {
		cfg.TLS.Certificate = storage.SiteCertFile(cfg.Host)
		cfg.TLS.Key = storage.SiteKeyFile(cfg.Host)
		cfg.TLS.Enabled = true
		cfg.Port = "https"

		// Is there a plaintext HTTP config for the same host? If not, make
		// one and have it redirect all requests to this HTTPS host.
		var plaintextHostFound bool
		for _, otherCfg := range allConfigs {
			if cfg.Host == otherCfg.Host && otherCfg.Port == "http" {
				plaintextHostFound = true
				break
			}
		}

		if !plaintextHostFound {
			// Make one that redirects to HTTPS for all requests
			allConfigs = append(allConfigs, redirPlaintextHost(*cfg))
		}
	}

	return allConfigs
}

// redirPlaintextHost returns a new plaintext HTTP configuration for
// a virtualHost that simply redirects to cfg, which is assumed to
// be the HTTPS configuration. The returned configuration is set
// to listen on the "http" port (port 80).
func redirPlaintextHost(cfg server.Config) server.Config {
	redirMidware := func(next middleware.Handler) middleware.Handler {
		return redirect.Redirect{Next: next, Rules: []redirect.Rule{
			{
				FromScheme: "http",
				FromPath:   "/",
				To:         "https://" + cfg.Host + "{uri}",
				Code:       http.StatusMovedPermanently,
			},
		}}
	}

	return server.Config{
		Host: cfg.Host,
		Port: "http",
		Middleware: map[string][]middleware.Middleware{
			"/": []middleware.Middleware{redirMidware},
		},
	}
}

var (
	// Let's Encrypt account email to use if none provided
	DefaultEmail string

	// Whether user has agreed to the Let's Encrypt SA
	Agreed bool
)

// Some essential values related to the Let's Encrypt process
const (
	// Size of RSA keys in bits
	rsaKeySize = 2048

	// The base URL to the Let's Encrypt CA
	caURL = "http://192.168.99.100:4000"

	// The port to expose to the CA server for Simple HTTP Challenge
	exposePort = "5001"
)

// KeySize represents the length of a key in bits
type KeySize int

// Key sizes
const (
	ECC_224  KeySize = 224
	ECC_256          = 256
	RSA_2048         = 2048
	RSA_4096         = 4096
)

type CertificateMeta struct {
	Domain, URL string
}
