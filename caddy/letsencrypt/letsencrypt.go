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

	"github.com/mholt/caddy/caddy/setup"
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

	// reset cached ocsp statuses from any previous activations
	ocspStatus = make(map[*[]byte]int)

	// Identify and configure any eligible hosts for which
	// we already have certs and keys in storage from last time.
	configLen := len(configs) // avoid infinite loop since this loop appends plaintext to the slice
	for i := 0; i < configLen; i++ {
		if existingCertAndKey(configs[i].Host) && configQualifies(configs, i) {
			configs = autoConfigure(configs, i)
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
	for leEmail, cfgIndexes := range groupedConfigs {
		// make client to service this email address with CA server
		client, err := newClient(leEmail)
		if err != nil {
			return configs, errors.New("error creating client: " + err.Error())
		}

		// little bit of housekeeping; gather the hostnames into a slice
		var hosts []string
		for _, idx := range cfgIndexes {
			// don't allow duplicates (happens when serving same host on multiple ports!)
			var duplicate bool
			for _, otherHost := range hosts {
				if configs[idx].Host == otherHost {
					duplicate = true
					break
				}
			}
			if !duplicate {
				hosts = append(hosts, configs[idx].Host)
			}
		}

		// client is ready, so let's get free, trusted SSL certificates!
	Obtain:
		certificates, failures := client.ObtainCertificates(hosts, true)
		if len(failures) > 0 {
			// Build an error string to return, using all the failures in the list.
			var errMsg string

			// If an error is because of updated SA, only prompt user for agreement once
			var promptedForAgreement bool

			for domain, obtainErr := range failures {
				// If the failure was simply because the terms have changed, re-prompt and re-try
				if tosErr, ok := obtainErr.(acme.TOSError); ok {
					if !Agreed && !promptedForAgreement {
						Agreed = promptUserAgreement(tosErr.Detail, true) // TODO: Use latest URL
						promptedForAgreement = true
					}
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
		for _, idx := range cfgIndexes {
			configs = autoConfigure(configs, idx)
		}
	}

	// renew all certificates that need renewal
	renewCertificates(configs, false)

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

// configQualifies returns true if the config at cfgIndex (within allConfigs)
// qualifes for automatic LE activation. It does NOT check to see if a cert
// and key already exist for the config.
func configQualifies(allConfigs []server.Config, cfgIndex int) bool {
	cfg := allConfigs[cfgIndex]
	return cfg.TLS.Certificate == "" && // user could provide their own cert and key
		cfg.TLS.Key == "" &&

		// user can force-disable automatic HTTPS for this host
		cfg.Port != "http" &&
		cfg.TLS.LetsEncryptEmail != "off" &&

		// obviously we get can't certs for loopback or internal hosts
		HostQualifies(cfg.Host) &&

		// make sure another HTTPS version of this config doesn't exist in the list already
		!otherHostHasScheme(allConfigs, cfgIndex, "https")
}

// HostQualifies returns true if the hostname alone
// appears eligible for automatic HTTPS. For example,
// localhost, empty hostname, and wildcard hosts are
// not eligible because we cannot obtain certificates
// for those names.
func HostQualifies(hostname string) bool {
	return hostname != "localhost" &&
		strings.TrimSpace(hostname) != "" &&
		hostname != "0.0.0.0" &&
		hostname != "[::]" && // before parsing
		hostname != "::" && // after parsing
		hostname != "[::1]" && // before parsing
		hostname != "::1" && // after parsing
		!strings.HasPrefix(hostname, "127.") // to use boulder on your own machine, add fake domain to hosts file
	// not excluding 10.* and 192.168.* hosts for possibility of running internal Boulder instance
}

// groupConfigsByEmail groups configs by user email address. The returned map is
// a map of email address to the configs that are serviced under that account.
// If an email address is not available for an eligible config, the user will be
// prompted to provide one. The returned map contains pointers to the original
// server config values.
func groupConfigsByEmail(configs []server.Config) (map[string][]int, error) {
	initMap := make(map[string][]int)
	for i := 0; i < len(configs); i++ {
		// filter out configs that we already have certs for and
		// that we won't be obtaining certs for - this way we won't
		// bother the user for an email address unnecessarily and
		// we don't obtain new certs for a host we already have certs for.
		if existingCertAndKey(configs[i].Host) || !configQualifies(configs, i) {
			continue
		}
		leEmail := getEmail(configs[i])
		initMap[leEmail] = append(initMap[leEmail], i)
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
	return newClientPort(leEmail, "")
}

// newClientPort does the same thing as newClient, except it creates a
// new client with a custom port used for ACME transactions instead of
// the default port. This is important if the default port is already in
// use or is not exposed to the public, etc.
func newClientPort(leEmail, port string) (*acme.Client, error) {
	// Look up or create the LE user account
	leUser, err := getUser(leEmail)
	if err != nil {
		return nil, err
	}

	// The client facilitates our communication with the CA server.
	client, err := acme.NewClient(CAUrl, &leUser, rsaKeySizeToUse, port)
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
func obtainCertificates(client *acme.Client, serverConfigs []server.Config) ([]acme.CertificateResource, map[string]error) {
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
		err := os.MkdirAll(storage.Site(cert.Domain), 0700)
		if err != nil {
			return err
		}

		// Save cert
		err = ioutil.WriteFile(storage.SiteCertFile(cert.Domain), cert.Certificate, 0600)
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

// autoConfigure enables TLS on allConfigs[cfgIndex] and appends, if necessary,
// a new config to allConfigs that redirects plaintext HTTP to its new HTTPS
// counterpart. It expects the certificate and key to already be in storage. It
// returns the new list of allConfigs, since it may append a new config. This
// function assumes that allConfigs[cfgIndex] is already set up for HTTPS.
func autoConfigure(allConfigs []server.Config, cfgIndex int) []server.Config {
	cfg := &allConfigs[cfgIndex]

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
	// Ensure all defaults are set for the TLS config
	setup.SetDefaultTLSParams(cfg)

	if cfg.Port == "" {
		cfg.Port = "https"
	}

	// Set up http->https redirect as long as there isn't already a http counterpart
	// in the configs and this isn't, for some reason, already on port 80.
	// Also, the port 80 variant of this config is necessary for proxying challenge requests.
	if !otherHostHasScheme(allConfigs, cfgIndex, "http") &&
		cfg.Port != "80" && cfg.Port != "http" { // (would not be http port with current program flow, but just in case)
		allConfigs = append(allConfigs, redirPlaintextHost(*cfg))
	}

	// To support renewals, we need handlers at ports 80 and 443,
	// depending on the challenge type that is used to complete renewal.
	for i, c := range allConfigs {
		if c.Address() == cfg.Host+":80" ||
			c.Address() == cfg.Host+":443" ||
			c.Address() == cfg.Host+":http" ||
			c.Address() == cfg.Host+":https" {

			// Each virtualhost must have their own handlers, or the chaining gets messed up when middlewares are compiled!
			handler := new(Handler)
			mid := func(next middleware.Handler) middleware.Handler {
				handler.Next = next
				return handler
			}
			// TODO: Currently, acmeHandlers are not referenced, but we need to add a way to toggle
			// their proxy functionality -- or maybe not. Gotta figure this out for sure.
			acmeHandlers[c.Address()] = handler

			allConfigs[i].Middleware["/"] = append(allConfigs[i].Middleware["/"], mid)
		}
	}

	return allConfigs
}

// otherHostHasScheme tells you whether there is ANOTHER config in allConfigs
// for the same host but with the port equal to scheme as allConfigs[cfgIndex].
// This function considers "443" and "https" to be the same scheme, as well as
// "http" and "80". It does not tell you whether there is ANY config with scheme,
// only if there's a different one with it.
func otherHostHasScheme(allConfigs []server.Config, cfgIndex int, scheme string) bool {
	if scheme == "80" {
		scheme = "http"
	} else if scheme == "443" {
		scheme = "https"
	}
	for i, otherCfg := range allConfigs {
		if i == cfgIndex {
			continue // has to be a config OTHER than the one we're comparing against
		}
		if otherCfg.Host == allConfigs[cfgIndex].Host {
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
	toURL := "https://" + cfg.Host
	if cfg.Port != "https" && cfg.Port != "http" {
		toURL += ":" + cfg.Port
	}

	redirMidware := func(next middleware.Handler) middleware.Handler {
		return redirect.Redirect{Next: next, Rules: []redirect.Rule{
			{
				FromScheme: "http",
				FromPath:   "/",
				To:         toURL + "{uri}",
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
	// DefaultEmail represents the Let's Encrypt account email to use if none provided
	DefaultEmail string

	// Agreed indicates whether user has agreed to the Let's Encrypt SA
	Agreed bool

	// CAUrl represents the base URL to the CA's ACME endpoint
	CAUrl string
)

// Some essential values related to the Let's Encrypt process
const (
	// alternatePort is the port on which the acme client will open a
	// listener and solve the CA's challenges. If this alternate port
	// is used instead of the default port (80 or 443), then the
	// default port for the challenge must be forwarded to this one.
	alternatePort = "5033"

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
