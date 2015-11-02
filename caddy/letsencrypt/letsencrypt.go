// Package letsencrypt integrates Let's Encrypt functionality into Caddy
// with first-class support for creating and renewing certificates
// automatically. It is designed to configure sites for HTTPS by default.
package letsencrypt

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/middleware/redirect"
	"github.com/mholt/caddy/server"
	"github.com/xenolf/lego/acme"
)

// Activate sets up TLS for each server config in configs
// as needed. It only skips the config if the cert and key
// are already provided, if plaintext http is explicitly
// specified as the port, TLS is explicitly disabled, or
// the host looks like a loopback or wildcard address.
//
// This function may prompt the user to provide an email
// address if none is available through other means. It
// prefers the email address specified in the config, but
// if that is not available it will check the command line
// argument. If absent, it will use the most recent email
// address from last time. If there isn't one, the user
// will be prompted and shown SA link.
//
// Also note that calling this function activates asset
// management automatically, which keeps certificates
// renewed and OCSP stapling updated. This has the effect
// of causing restarts when assets are updated.
//
// Activate returns the updated list of configs, since
// some may have been appended, for example, to redirect
// plaintext HTTP requests to their HTTPS counterpart.
// This function only appends; it does not prepend or splice.
func Activate(configs []server.Config) ([]server.Config, error) {
	// just in case previous caller forgot...
	Deactivate()

	// TODO: All the output the end user should see when running caddy is something
	// simple like "Setting up HTTPS..." (and maybe 'done' at the end of the line when finished).
	// In other words, hide all the other logging except for on errors. Or maybe
	// have a place to put those logs.

	// reset cached ocsp statuses from any previous activations
	ocspStatus = make(map[*[]byte]int)

	// Identify and configure any eligible hosts for which
	// we already have certs and keys in storage from last time.
	configLen := len(configs) // avoid infinite loop since this loop appends plaintext to the slice
	for i := 0; i < configLen; i++ {
		if existingCertAndKey(configs[i].Host) && configQualifies(configs[i], configs) {
			configs = autoConfigure(&configs[i], configs)
		}
	}

	// Group configs by email address; only configs that are eligible
	// for TLS management are included. We group by email so that we
	// can request certificates in batches with the same client.
	// Note: The return value is a map, and iteration over a map is
	// not ordered. I don't think it will be a problem, but if an
	// ordering problem arises, look at this carefully.
	groupedConfigs, err := groupConfigsByEmail(configs)
	if err != nil {
		return configs, err
	}

	// obtain certificates for configs that need one, and reconfigure each
	// config to use the certificates
	for leEmail, serverConfigs := range groupedConfigs {
		// make client to service this email address with CA server
		client, err := newClient(leEmail)
		if err != nil {
			return configs, errors.New("error creating client: " + err.Error())
		}

		// client is ready, so let's get free, trusted SSL certificates! yeah!
	Obtain:
		certificates, failures := obtainCertificates(client, serverConfigs)
		if len(failures) > 0 {
			// Build an error string to return, using all the failures in the list.
			var errMsg string

			// An agreement error means we need to prompt the user (once) with updated terms
			// while they're still here.
			var promptedUpdatedTerms bool

			for domain, obtainErr := range failures {
				// If the failure was simply because the terms have changed, re-prompt and re-try
				if tosErr, ok := obtainErr.(acme.TOSError); ok && !promptedUpdatedTerms {
					Agreed = promptUserAgreement(tosErr.Detail, true) // TODO: Use latest URL
					promptedUpdatedTerms = true
					if Agreed {
						err := client.AgreeToTOS()
						if err != nil {
							return configs, errors.New("error agreeing to updated terms: " + err.Error())
						}
						goto Obtain
					}
				}

				// If user did not agree or it was any other kind of error, just append to the list of errors
				errMsg += "[" + domain + "] failed to get certificate: " + obtainErr.Error() + "\n"
			}

			return configs, errors.New(errMsg)
		}

		// ... that's it. save the certs, keys, and metadata files to disk
		err = saveCertsAndKeys(certificates)
		if err != nil {
			return configs, errors.New("error saving assets: " + err.Error())
		}

		// it all comes down to this: turning on TLS with all the new certs
		for i := 0; i < len(serverConfigs); i++ {
			configs = autoConfigure(serverConfigs[i], configs)
		}
	}

	// renew all certificates that need renewal
	renewCertificates(configs)

	// keep certificates renewed and OCSP stapling updated
	go maintainAssets(configs, stopChan)

	return configs, nil
}

// Deactivate cleans up long-term, in-memory resources
// allocated by calling Activate(). Essentially, it stops
// the asset maintainer from running, meaning that certificates
// will not be renewed, OCSP staples will not be updated, etc.
func Deactivate() (err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = errors.New("already deactivated")
		}
	}()
	close(stopChan)
	stopChan = make(chan struct{})
	return
}

// configQualifies returns true if cfg qualifes for automatic LE activation,
// but it does require the list of all configs to be passed in as well.
// It does NOT check to see if a cert and key already exist for cfg.
func configQualifies(cfg server.Config, allConfigs []server.Config) bool {
	return cfg.TLS.Certificate == "" && // user could provide their own cert and key
		cfg.TLS.Key == "" &&

		// user can force-disable automatic HTTPS for this host
		cfg.Port != "http" &&
		cfg.TLS.LetsEncryptEmail != "off" &&

		// obviously we get can't certs for loopback or internal hosts
		cfg.Host != "localhost" &&
		cfg.Host != "" &&
		cfg.Host != "0.0.0.0" &&
		cfg.Host != "::1" &&
		!strings.HasPrefix(cfg.Host, "127.") &&
		// TODO: Also exclude 10.* and 192.168.* addresses?

		// make sure an HTTPS version of this config doesn't exist in the list already
		!hostHasOtherScheme(cfg.Host, "https", allConfigs)
}

// groupConfigsByEmail groups configs by user email address. The returned map is
// a map of email address to the configs that are serviced under that account.
// If an email address is not available for an eligible config, the user will be
// prompted to provide one. The returned map contains pointers to the original
// server config values.
func groupConfigsByEmail(configs []server.Config) (map[string][]*server.Config, error) {
	initMap := make(map[string][]*server.Config)
	for i := 0; i < len(configs); i++ {
		// filter out configs that we already have certs for and
		// that we won't be obtaining certs for - this way we won't
		// bother the user for an email address unnecessarily and
		// we don't obtain new certs for a host we already have certs for.
		if existingCertAndKey(configs[i].Host) || !configQualifies(configs[i], configs) {
			continue
		}
		leEmail := getEmail(configs[i])
		initMap[leEmail] = append(initMap[leEmail], &configs[i])
	}
	return initMap, nil
}

// existingCertAndKey returns true if the host has a certificate
// and private key in storage already, false otherwise.
func existingCertAndKey(host string) bool {
	_, err := os.Stat(storage.SiteCertFile(host))
	if err != nil {
		return false
	}
	_, err = os.Stat(storage.SiteKeyFile(host))
	if err != nil {
		return false
	}
	return true
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
	client, err := acme.NewClient(CAUrl, &leUser, rsaKeySizeToUse, exposePort)
	if err != nil {
		return nil, err
	}

	// If not registered, the user must register an account with the CA
	// and agree to terms
	if leUser.Registration == nil {
		reg, err := client.Register()
		if err != nil {
			return nil, errors.New("registration error: " + err.Error())
		}
		leUser.Registration = reg

		if !Agreed && reg.TosURL == "" {
			Agreed = promptUserAgreement(saURL, false) // TODO - latest URL
		}
		if !Agreed && reg.TosURL == "" {
			return nil, errors.New("user must agree to terms")
		}

		err = client.AgreeToTOS()
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
func obtainCertificates(client *acme.Client, serverConfigs []*server.Config) ([]acme.CertificateResource, map[string]error) {
	// collect all the hostnames into one slice
	var hosts []string
	for _, cfg := range serverConfigs {
		hosts = append(hosts, cfg.Host)
	}

	return client.ObtainCertificates(hosts, true)
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
		jsonBytes, err := json.MarshalIndent(&cert, "", "\t")
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

// autoConfigure enables TLS on cfg and appends, if necessary, a new config
// to allConfigs that redirects plaintext HTTP to its new HTTPS counterpart.
// It expects the certificate and key to already be in storage. It returns
// the new list of allConfigs, since it may append a new config. This function
// assumes that cfg was already set up for HTTPS.
func autoConfigure(cfg *server.Config, allConfigs []server.Config) []server.Config {
	bundleBytes, err := ioutil.ReadFile(storage.SiteCertFile(cfg.Host))
	// TODO: Handle these errors better
	if err == nil {
		ocsp, status, err := acme.GetOCSPForCert(bundleBytes)
		ocspStatus[&bundleBytes] = status
		if err == nil && status == acme.OCSPGood {
			cfg.TLS.OCSPStaple = ocsp
		}
	}
	cfg.TLS.Certificate = storage.SiteCertFile(cfg.Host)
	cfg.TLS.Key = storage.SiteKeyFile(cfg.Host)
	cfg.TLS.Enabled = true
	if cfg.Port == "" {
		cfg.Port = "https"
	}

	// Set up http->https redirect as long as there isn't already
	// a http counterpart in the configs
	if !hostHasOtherScheme(cfg.Host, "http", allConfigs) {
		allConfigs = append(allConfigs, redirPlaintextHost(*cfg))
	}

	return allConfigs
}

// hostHasOtherScheme tells you whether there is another config in the list
// for the same host but with the port equal to scheme. For example, to see
// if example.com has a https variant already, pass in example.com and
// "https" along with the list of configs. This function considers "443"
// and "https" to be the same scheme, as well as "http" and "80".
func hostHasOtherScheme(host, scheme string, allConfigs []server.Config) bool {
	if scheme == "80" {
		scheme = "http"
	} else if scheme == "443" {
		scheme = "https"
	}
	for _, otherCfg := range allConfigs {
		if otherCfg.Host == host {
			if (otherCfg.Port == scheme) ||
				(scheme == "https" && otherCfg.Port == "443") ||
				(scheme == "http" && otherCfg.Port == "80") {
				return true
			}
		}
	}
	return false
}

// redirPlaintextHost returns a new plaintext HTTP configuration for
// a virtualHost that simply redirects to cfg, which is assumed to
// be the HTTPS configuration. The returned configuration is set
// to listen on the "http" port (port 80).
func redirPlaintextHost(cfg server.Config) server.Config {
	toUrl := "https://" + cfg.Host
	if cfg.Port != "https" && cfg.Port != "http" {
		toUrl += ":" + cfg.Port
	}

	redirMidware := func(next middleware.Handler) middleware.Handler {
		return redirect.Redirect{Next: next, Rules: []redirect.Rule{
			{
				FromScheme: "http",
				FromPath:   "/",
				To:         toUrl + "{uri}",
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

// Revoke revokes the certificate for host via ACME protocol.
func Revoke(host string) error {
	if !existingCertAndKey(host) {
		return errors.New("no certificate and key for " + host)
	}

	email := getEmail(server.Config{Host: host})
	if email == "" {
		return errors.New("email is required to revoke")
	}

	client, err := newClient(email)
	if err != nil {
		return err
	}

	certFile := storage.SiteCertFile(host)
	certBytes, err := ioutil.ReadFile(certFile)
	if err != nil {
		return err
	}

	err = client.RevokeCertificate(certBytes)
	if err != nil {
		return err
	}

	err = os.Remove(certFile)
	if err != nil {
		return errors.New("certificate revoked, but unable to delete certificate file: " + err.Error())
	}

	return nil
}

var (
	// Let's Encrypt account email to use if none provided
	DefaultEmail string

	// Whether user has agreed to the Let's Encrypt SA
	Agreed bool

	// The base URL to the CA's ACME endpoint
	CAUrl string
)

// Some essential values related to the Let's Encrypt process
const (
	// The port to expose to the CA server for Simple HTTP Challenge.
	// NOTE: Let's Encrypt requires port 443. If exposePort is not 443,
	// then port 443 must be forwarded to exposePort.
	exposePort = "443"

	// How often to check certificates for renewal.
	renewInterval = 24 * time.Hour

	// How often to update OCSP stapling.
	ocspInterval = 1 * time.Hour
)

// KeySize represents the length of a key in bits.
type KeySize int

// Key sizes are used to determine the strength of a key.
const (
	ECC_224  KeySize = 224
	ECC_256          = 256
	RSA_2048         = 2048
	RSA_4096         = 4096
)

// rsaKeySizeToUse is the size to use for new RSA keys.
// This shouldn't need to change except for in tests;
// the size can be drastically reduced for speed.
var rsaKeySizeToUse = RSA_2048

// stopChan is used to signal the maintenance goroutine
// to terminate.
var stopChan chan struct{}

// ocspStatus maps certificate bundle to OCSP status at start.
// It is used during regular OCSP checks to see if the OCSP
// status has changed.
var ocspStatus = make(map[*[]byte]int)
