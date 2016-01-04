// Package letsencrypt integrates Let's Encrypt functionality into Caddy
// with first-class support for creating and renewing certificates
// automatically. It is designed to configure sites for HTTPS by default.
package letsencrypt

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/mholt/caddy/caddy/setup"
	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/middleware/redirect"
	"github.com/mholt/caddy/server"
	"github.com/xenolf/lego/acme"
)

func configureExisting(configs []server.Config) []server.Config {
	// Identify and configure any eligible hosts for which
	// we already have certs and keys in storage from last time.
	configLen := len(configs) // avoid infinite loop since this loop appends plaintext to the slice
	for i := 0; i < configLen; i++ {
		if existingCertAndKey(configs[i].Host) && ConfigQualifies(configs, i) {
			configs = autoConfigure(configs, i)
		}
	}
	return configs
}

// ObtainCertsAndConfigure obtains certificates for all qualifying configs.
func ObtainCertsAndConfigure(configs []server.Config, optPort string) ([]server.Config, error) {
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
	finishedHosts := make(map[string]struct{})
	for leEmail, cfgIndexes := range groupedConfigs {
		// make client to service this email address with CA server
		client, err := newClientPort(leEmail, optPort)
		if err != nil {
			return configs, errors.New("error creating client: " + err.Error())
		}

		// let's get free, trusted SSL certificates!
		for _, idx := range cfgIndexes {
			hostname := configs[idx].Host

			// prevent duplicate efforts, for example, when host is served on multiple ports
			if _, ok := finishedHosts[hostname]; ok {
				continue
			}
			finishedHosts[hostname] = struct{}{}

		Obtain:
			certificate, failures := client.ObtainCertificate([]string{hostname}, true)
			if len(failures) == 0 {
				// Success - immediately save the certificate resource
				err := saveCertResource(certificate)
				if err != nil {
					return configs, errors.New("error saving assets for " + hostname + ": " + err.Error())
				}
			} else {
				// Error - either try to fix it or report them it to the user and abort
				var errMsg string             // we'll combine all the failures into a single error message
				var promptedForAgreement bool // only prompt user for agreement at most once

				for errDomain, obtainErr := range failures {
					if obtainErr != nil {
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
						errMsg += "[" + errDomain + "] failed to get certificate: " + obtainErr.Error() + "\n"
					}
				}

				return configs, errors.New(errMsg)
			}
		}

		// it all comes down to this: turning on TLS with all the new certs
		for _, idx := range cfgIndexes {
			configs = autoConfigure(configs, idx)
		}
	}

	return configs, nil
}

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
	var err error

	// just in case previous caller forgot...
	Deactivate()

	// reset cached ocsp from any previous activations
	ocspCache = make(map[*[]byte]*ocsp.Response)

	// configure configs for which we have an existing certificate
	configs = configureExisting(configs)

	// obtain certificates for configs which need one, and make them use them
	configs, err = ObtainCertsAndConfigure(configs, "")
	if err != nil {
		return configs, err
	}

	// renew all relevant certificates that need renewal; TODO: handle errors
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

// ConfigQualifies returns true if the config at cfgIndex (within allConfigs)
// qualifes for automatic LE activation. It does NOT check to see if a cert
// and key already exist for the config.
func ConfigQualifies(allConfigs []server.Config, cfgIndex int) bool {
	cfg := allConfigs[cfgIndex]
	return cfg.TLS.Certificate == "" && // user could provide their own cert and key
		cfg.TLS.Key == "" &&

		// user can force-disable automatic HTTPS for this host
		cfg.Scheme != "http" &&
		cfg.Port != "80" &&
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
		net.ParseIP(hostname) == nil && // cannot be an IP address, see: https://community.letsencrypt.org/t/certificate-for-static-ip/84/2?u=mholt
		hostname != "[::]" && // before parsing
		hostname != "::" && // after parsing
		hostname != "[::1]" && // before parsing
		hostname != "::1" // after parsing
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
		if existingCertAndKey(configs[i].Host) || !ConfigQualifies(configs, i) {
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
	client, err := acme.NewClient(CAUrl, &leUser, rsaKeySizeToUse)
	if err != nil {
		return nil, err
	}
	client.SetHTTPPort(port)
	client.SetTLSPort(port)
	client.ExcludeChallenges([]string{"tls-sni-01", "dns-01"}) // We can only guarantee http-01 at this time

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

// saveCertResource saves the certificate resource to disk. This
// includes the certificate file itself, the private key, and the
// metadata file.
func saveCertResource(cert acme.CertificateResource) error {
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
		ocspBytes, ocspResp, err := acme.GetOCSPForCert(bundleBytes)
		ocspCache[&bundleBytes] = ocspResp
		if err == nil && ocspResp.Status == ocsp.Good {
			cfg.TLS.OCSPStaple = ocspBytes
		}
	}
	cfg.TLS.Certificate = storage.SiteCertFile(cfg.Host)
	cfg.TLS.Key = storage.SiteKeyFile(cfg.Host)
	cfg.TLS.Enabled = true
	setup.SetDefaultTLSParams(cfg)

	if cfg.Port == "" {
		cfg.Port = "443"
	}

	// Set up http->https redirect as long as there isn't already a http counterpart
	// in the configs and this isn't, for some reason, already on port 80.
	// Also, the port 80 variant of this config is necessary for proxying challenge requests.
	if !otherHostHasScheme(allConfigs, cfgIndex, "http") && cfg.Port != "80" && cfg.Scheme != "http" {
		allConfigs = append(allConfigs, redirPlaintextHost(*cfg))
	}

	return allConfigs
}

// otherHostHasScheme tells you whether there is ANOTHER config in allConfigs
// for the same host but with the port equal to scheme as allConfigs[cfgIndex].
// This function considers "443" and "https" to be the same scheme, as well as
// "http" and "80". It does not tell you whether there is ANY config with scheme,
// only if there's a different one with it.
func otherHostHasScheme(allConfigs []server.Config, cfgIndex int, scheme string) bool {
	if scheme == "http" {
		scheme = "80"
	} else if scheme == "https" {
		scheme = "443"
	}
	for i, otherCfg := range allConfigs {
		if i == cfgIndex {
			continue // has to be a config OTHER than the one we're comparing against
		}
		if otherCfg.Host == allConfigs[cfgIndex].Host && otherCfg.Port == scheme {
			return true
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
	if cfg.Port != "443" && cfg.Port != "80" {
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
		Port: "80",
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
	// AlternatePort is the port on which the acme client will open a
	// listener and solve the CA's challenges. If this alternate port
	// is used instead of the default port (80 or 443), then the
	// default port for the challenge must be forwarded to this one.
	AlternatePort = "5033"

	// RenewInterval is how often to check certificates for renewal.
	RenewInterval = 24 * time.Hour

	// OCSPInterval is how often to check if OCSP stapling needs updating.
	OCSPInterval = 1 * time.Hour
)

// KeySize represents the length of a key in bits.
type KeySize int

// Key sizes are used to determine the strength of a key.
const (
	Ecc224  KeySize = 224
	Ecc256          = 256
	Rsa2048         = 2048
	Rsa4096         = 4096
)

// rsaKeySizeToUse is the size to use for new RSA keys.
// This shouldn't need to change except for in tests;
// the size can be drastically reduced for speed.
var rsaKeySizeToUse = Rsa2048

// stopChan is used to signal the maintenance goroutine
// to terminate.
var stopChan chan struct{}

// ocspCache maps certificate bundle to OCSP response.
// It is used during regular OCSP checks to see if the OCSP
// response needs to be updated.
var ocspCache = make(map[*[]byte]*ocsp.Response)
