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

// Activate sets up TLS for each server config in configs
// as needed; this consists of acquiring and maintaining
// certificates and keys for qualifying configs and enabling
// OCSP stapling for all TLS-enabled configs.
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

	// reset cached ocsp from any previous activations
	ocspCache = make(map[*[]byte]*ocsp.Response)

	// pre-screen each config and earmark the ones that qualify for managed TLS
	MarkQualified(configs)

	// place certificates and keys on disk
	err := ObtainCerts(configs, "")
	if err != nil {
		return configs, err
	}

	// update TLS configurations
	EnableTLS(configs)

	// enable OCSP stapling (this affects all TLS-enabled configs)
	err = StapleOCSP(configs)
	if err != nil {
		return configs, err
	}

	// set up redirects
	configs = MakePlaintextRedirects(configs)

	// renew all relevant certificates that need renewal. this is important
	// to do right away for a couple reasons, mainly because each restart,
	// the renewal ticker is reset, so if restarts happen more often than
	// the ticker interval, renewals would never happen. but doing
	// it right away at start guarantees that renewals aren't missed.
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

// MarkQualified scans each config and, if it qualifies for managed
// TLS, it sets the Marked field of the TLSConfig to true.
func MarkQualified(configs []server.Config) {
	for i := 0; i < len(configs); i++ {
		if ConfigQualifies(configs[i]) {
			configs[i].TLS.Managed = true
		}
	}
}

// ObtainCerts obtains certificates for all these configs as long as a certificate does not
// already exist on disk. It does not modify the configs at all; it only obtains and stores
// certificates and keys to the disk.
func ObtainCerts(configs []server.Config, altPort string) error {
	groupedConfigs := groupConfigsByEmail(configs, altPort != "") // don't prompt user if server already running

	for email, group := range groupedConfigs {
		client, err := newClientPort(email, altPort)
		if err != nil {
			return errors.New("error creating client: " + err.Error())
		}

		for _, cfg := range group {
			if existingCertAndKey(cfg.Host) {
				continue
			}

		Obtain:
			certificate, failures := client.ObtainCertificate([]string{cfg.Host}, true, nil)
			if len(failures) == 0 {
				// Success - immediately save the certificate resource
				err := saveCertResource(certificate)
				if err != nil {
					return errors.New("error saving assets for " + cfg.Host + ": " + err.Error())
				}
			} else {
				// Error - either try to fix it or report them it to the user and abort
				var errMsg string             // we'll combine all the failures into a single error message
				var promptedForAgreement bool // only prompt user for agreement at most once

				for errDomain, obtainErr := range failures {
					// TODO: Double-check, will obtainErr ever be nil?
					if tosErr, ok := obtainErr.(acme.TOSError); ok {
						// Terms of Service agreement error; we can probably deal with this
						if !Agreed && !promptedForAgreement && altPort == "" { // don't prompt if server is already running
							Agreed = promptUserAgreement(tosErr.Detail, true) // TODO: Use latest URL
							promptedForAgreement = true
						}
						if Agreed || altPort != "" {
							err := client.AgreeToTOS()
							if err != nil {
								return errors.New("error agreeing to updated terms: " + err.Error())
							}
							goto Obtain
						}
					}

					// If user did not agree or it was any other kind of error, just append to the list of errors
					errMsg += "[" + errDomain + "] failed to get certificate: " + obtainErr.Error() + "\n"
				}

				return errors.New(errMsg)
			}
		}
	}

	return nil
}

// groupConfigsByEmail groups configs by the email address to be used by its
// ACME client. It only includes configs that are marked as fully managed.
// This is the function that may prompt for an email address, unless skipPrompt
// is true, in which case it will assume an empty email address.
func groupConfigsByEmail(configs []server.Config, skipPrompt bool) map[string][]server.Config {
	initMap := make(map[string][]server.Config)
	for _, cfg := range configs {
		if !cfg.TLS.Managed {
			continue
		}
		leEmail := getEmail(cfg, skipPrompt)
		initMap[leEmail] = append(initMap[leEmail], cfg)
	}
	return initMap
}

// EnableTLS configures each config to use TLS according to default settings.
// It will only change configs that are marked as managed, and assumes that
// certificates and keys are already on disk.
func EnableTLS(configs []server.Config) {
	for i := 0; i < len(configs); i++ {
		if !configs[i].TLS.Managed {
			continue
		}
		configs[i].TLS.Enabled = true
		configs[i].TLS.Certificate = storage.SiteCertFile(configs[i].Host)
		configs[i].TLS.Key = storage.SiteKeyFile(configs[i].Host)
		setup.SetDefaultTLSParams(&configs[i])
	}
}

// StapleOCSP staples OCSP responses to each config according to their certificate.
// This should work for any TLS-enabled config, not just Let's Encrypt ones.
func StapleOCSP(configs []server.Config) error {
	for i := 0; i < len(configs); i++ {
		if configs[i].TLS.Certificate == "" {
			continue
		}

		bundleBytes, err := ioutil.ReadFile(configs[i].TLS.Certificate)
		if err != nil {
			return errors.New("load certificate to staple ocsp: " + err.Error())
		}

		ocspBytes, ocspResp, err := acme.GetOCSPForCert(bundleBytes)
		if err == nil {
			// TODO: We ignore the error if it exists because some certificates
			// may not have an issuer URL which we should ignore anyway, and
			// sometimes we get syntax errors in the responses. To reproduce this
			// behavior, start Caddy with an empty Caddyfile and -log stderr. Then
			// add a host to the Caddyfile which requires a new LE certificate.
			// Reload Caddy's config with SIGUSR1, and see the log report that it
			// obtains the certificate, but then an error:
			// getting ocsp: asn1: syntax error: sequence truncated
			// But retrying the reload again sometimes solves the problem. It's flaky...
			ocspCache[&bundleBytes] = ocspResp
			if ocspResp.Status == ocsp.Good {
				configs[i].TLS.OCSPStaple = ocspBytes
			}
		}
	}
	return nil
}

// hostHasOtherPort returns true if there is another config in the list with the same
// hostname that has port otherPort, or false otherwise. All the configs are checked
// against the hostname of allConfigs[thisConfigIdx].
func hostHasOtherPort(allConfigs []server.Config, thisConfigIdx int, otherPort string) bool {
	for i, otherCfg := range allConfigs {
		if i == thisConfigIdx {
			continue // has to be a config OTHER than the one we're comparing against
		}
		if otherCfg.Host == allConfigs[thisConfigIdx].Host && otherCfg.Port == otherPort {
			return true
		}
	}
	return false
}

// MakePlaintextRedirects sets up redirects from port 80 to the relevant HTTPS
// hosts. You must pass in all configs, not just configs that qualify, since
// we must know whether the same host already exists on port 80, and those would
// not be in a list of configs that qualify for automatic HTTPS. This function will
// only set up redirects for configs that qualify. It returns the updated list of
// all configs.
func MakePlaintextRedirects(allConfigs []server.Config) []server.Config {
	for i, cfg := range allConfigs {
		if cfg.TLS.Managed &&
			!hostHasOtherPort(allConfigs, i, "80") &&
			(cfg.Port == "443" || !hostHasOtherPort(allConfigs, i, "443")) {
			allConfigs = append(allConfigs, redirPlaintextHost(cfg))
		}
	}
	return allConfigs
}

// ConfigQualifies returns true if cfg qualifies for
// fully managed TLS. It does NOT check to see if a
// cert and key already exist for the config. If the
// config does qualify, you should set cfg.TLS.Managed
// to true and use that instead, because the process of
// setting up the config may make it look like it
// doesn't qualify even though it originally did.
func ConfigQualifies(cfg server.Config) bool {
	return cfg.TLS.Certificate == "" && // user could provide their own cert and key
		cfg.TLS.Key == "" &&

		// user can force-disable automatic HTTPS for this host
		cfg.Scheme != "http" &&
		cfg.Port != "80" &&
		cfg.TLS.LetsEncryptEmail != "off" &&

		// we get can't certs for some kinds of hostnames
		HostQualifies(cfg.Host)
}

// HostQualifies returns true if the hostname alone
// appears eligible for automatic HTTPS. For example,
// localhost, empty hostname, and wildcard hosts are
// not eligible because we cannot obtain certificates
// for those names.
func HostQualifies(hostname string) bool {
	return hostname != "localhost" && // localhost is ineligible

		// hostname must not be empty
		strings.TrimSpace(hostname) != "" &&

		// cannot be an IP address, see
		// https://community.letsencrypt.org/t/certificate-for-static-ip/84/2?u=mholt
		// (also trim [] from either end, since that special case can sneak through
		// for IPv6 addresses using the -host flag and with empty/no Caddyfile)
		net.ParseIP(strings.Trim(hostname, "[]")) == nil
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
	if port != "" {
		client.SetHTTPAddress(":" + port)
		client.SetTLSAddress(":" + port)
	}
	client.ExcludeChallenges([]string{"tls-sni-01", "dns-01"}) // We can only guarantee http-01 at this time, but tls-01 should work if port is not custom!

	// If not registered, the user must register an account with the CA
	// and agree to terms
	if leUser.Registration == nil {
		reg, err := client.Register()
		if err != nil {
			return nil, errors.New("registration error: " + err.Error())
		}
		leUser.Registration = reg

		if port == "" { // can't prompt a user who isn't there
			if !Agreed && reg.TosURL == "" {
				Agreed = promptUserAgreement(saURL, false) // TODO - latest URL
			}
			if !Agreed && reg.TosURL == "" {
				return nil, errors.New("user must agree to terms")
			}
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

// redirPlaintextHost returns a new plaintext HTTP configuration for
// a virtualHost that simply redirects to cfg, which is assumed to
// be the HTTPS configuration. The returned configuration is set
// to listen on port 80.
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
		Host:     cfg.Host,
		BindHost: cfg.BindHost,
		Port:     "80",
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

	email := getEmail(server.Config{Host: host}, false)
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
