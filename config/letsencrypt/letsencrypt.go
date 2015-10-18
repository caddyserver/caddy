package letsencrypt

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/middleware/redirect"
	"github.com/mholt/caddy/server"
	"github.com/xenolf/lego/acme"
)

// Activate sets up TLS for each server config in configs
// as needed. It only skips the config if the cert and key
// are already provided or if plaintext http is explicitly
// specified as the port.
func Activate(configs []server.Config) ([]server.Config, error) {
	// populate map of email address to server configs that use that email address for TLS.
	// this will help us reduce roundtrips when getting the certs.
	initMap := make(map[string][]*server.Config)
	for i := 0; i < len(configs); i++ {
		if configs[i].TLS.Certificate == "" && configs[i].TLS.Key == "" && configs[i].Port != "http" { // TODO: && !cfg.Host.IsLoopback()
			leEmail := getEmail(configs[i])
			if leEmail == "" {
				return configs, errors.New("cannot serve HTTPS without email address OR certificate and key")
			}
			initMap[leEmail] = append(initMap[leEmail], &configs[i])
		}
	}

	// Loop through each email address and obtain certs; we can obtain more
	// than one certificate per email address, and still save them individually.
	for leEmail, serverConfigs := range initMap {
		// Look up or create the LE user account
		leUser, err := getUser(leEmail)
		if err != nil {
			return configs, err
		}

		// The client facilitates our communication with the CA server.
		client := acme.NewClient(caURL, &leUser, rsaKeySize, exposePort)

		// If not registered, the user must register an account with the CA
		// and agree to terms
		if leUser.Registration == nil {
			reg, err := client.Register()
			if err != nil {
				return configs, errors.New("registration error: " + err.Error())
			}
			leUser.Registration = reg

			// TODO: we can just do the agreement once, when registering, right?
			err = client.AgreeToTos()
			if err != nil {
				saveUser(leUser) // TODO: Might as well try, right? Error check?
				return configs, errors.New("error agreeing to terms: " + err.Error())
			}

			err = saveUser(leUser)
			if err != nil {
				return configs, errors.New("could not save user: " + err.Error())
			}
		}

		// collect all the hostnames into one slice
		var hosts []string
		for _, cfg := range serverConfigs {
			hosts = append(hosts, cfg.Host)
		}

		// showtime: let's get free, trusted SSL certificates! yeah!
		certificates, err := client.ObtainCertificates(hosts)
		if err != nil {
			return configs, errors.New("error obtaining certs: " + err.Error())
		}

		// ... that's it. save the certs, keys, and update server configs.
		for _, cert := range certificates {
			os.MkdirAll(storage.Site(cert.Domain), 0700)

			// Save cert
			err = saveCertificate(cert.Certificate, storage.SiteCertFile(cert.Domain))
			if err != nil {
				return configs, err
			}

			// Save private key
			err = ioutil.WriteFile(storage.SiteKeyFile(cert.Domain), cert.PrivateKey, 0600)
			if err != nil {
				return configs, err
			}

			// Save cert metadata
			jsonBytes, err := json.MarshalIndent(&CertificateMeta{URL: cert.CertURL, Domain: cert.Domain}, "", "\t")
			if err != nil {
				return configs, err
			}
			err = ioutil.WriteFile(storage.SiteMetaFile(cert.Domain), jsonBytes, 0600)
			if err != nil {
				return configs, err
			}
		}

		// it all comes down to this: filling in the file path of a valid certificate automatically
		for _, cfg := range serverConfigs {
			cfg.TLS.Certificate = storage.SiteCertFile(cfg.Host)
			cfg.TLS.Key = storage.SiteKeyFile(cfg.Host)
			cfg.TLS.Enabled = true
			cfg.Port = "https"

			// Is there a plaintext HTTP config for the same host? If not, make
			// one and have it redirect all requests to this HTTPS host.
			var plaintextHostFound bool
			for _, otherCfg := range configs {
				if cfg.Host == otherCfg.Host && otherCfg.Port == "http" {
					plaintextHostFound = true
					break
				}
			}

			if !plaintextHostFound {
				// Make one that redirects to HTTPS for all requests
				configs = append(configs, redirPlaintextHost(*cfg))
			}
		}
	}

	return configs, nil
}

// redirPlaintextHost returns a new virtualhost configuration for a server
// that redirects the plaintext HTTP host of cfg to cfg, which is assumed
// to be the secure (HTTPS) host.
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

// getEmail does everything it can to obtain an email
// address from the user to use for TLS for cfg. If it
// cannot get an email address, it returns empty string.
func getEmail(cfg server.Config) string {
	// First try the tls directive from the Caddyfile
	leEmail := cfg.TLS.LetsEncryptEmail
	if leEmail == "" {
		// Then try memory (command line flag or typed by user previously)
		leEmail = DefaultEmail
	}
	if leEmail == "" {
		// Then try to get most recent user email ~/.caddy/users file
		// TODO: Probably better to open the user's json file and read the email out of there...
		userDirs, err := ioutil.ReadDir(storage.Users())
		if err == nil {
			var mostRecent os.FileInfo
			for _, dir := range userDirs {
				if !dir.IsDir() {
					continue
				}
				if mostRecent == nil || dir.ModTime().After(mostRecent.ModTime()) {
					mostRecent = dir
				}
			}
			if mostRecent != nil {
				leEmail = mostRecent.Name()
			}
		}
	}
	if leEmail == "" {
		// Alas, we must bother the user and ask for an email address
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Email address: ") // TODO: More explanation probably, and show ToS?
		var err error
		leEmail, err = reader.ReadString('\n')
		if err != nil {
			return ""
		}
		DefaultEmail = leEmail
	}
	return strings.TrimSpace(leEmail)
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
