// Package https facilitates the management of TLS assets and integrates
// Let's Encrypt functionality into Caddy with first-class support for
// creating and renewing certificates automatically. It is designed to
// configure sites for HTTPS by default.
package https

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"

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
// renewed and OCSP stapling updated.
//
// Activate returns the updated list of configs, since
// some may have been appended, for example, to redirect
// plaintext HTTP requests to their HTTPS counterpart.
// This function only appends; it does not splice.
func Activate(configs []server.Config) ([]server.Config, error) {
	// just in case previous caller forgot...
	Deactivate()

	// pre-screen each config and earmark the ones that qualify for managed TLS
	MarkQualified(configs)

	// place certificates and keys on disk
	err := ObtainCerts(configs, true, false)
	if err != nil {
		return configs, err
	}

	// update TLS configurations
	err = EnableTLS(configs, true)
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
	err = renewManagedCertificates(true)
	if err != nil {
		return configs, err
	}

	// keep certificates renewed and OCSP stapling updated
	go maintainAssets(stopChan)

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
// TLS, it sets the Managed field of the TLSConfig to true.
func MarkQualified(configs []server.Config) {
	for i := 0; i < len(configs); i++ {
		if ConfigQualifies(configs[i]) {
			configs[i].TLS.Managed = true
		}
	}
}

// ObtainCerts obtains certificates for all these configs as long as a
// certificate does not already exist on disk. It does not modify the
// configs at all; it only obtains and stores certificates and keys to
// the disk. If allowPrompts is true, the user may be shown a prompt.
// If proxyACME is true, the ACME challenges will be proxied to our alt port.
func ObtainCerts(configs []server.Config, allowPrompts, proxyACME bool) error {
	// We group configs by email so we don't make the same clients over and
	// over. This has the potential to prompt the user for an email, but we
	// prevent that by assuming that if we already have a listener that can
	// proxy ACME challenge requests, then the server is already running and
	// the operator is no longer present.
	groupedConfigs := groupConfigsByEmail(configs, allowPrompts)

	for email, group := range groupedConfigs {
		// Wait as long as we can before creating the client, because it
		// may not be needed, for example, if we already have what we
		// need on disk. Creating a client involves the network and
		// potentially prompting the user, etc., so only do if necessary.
		var client *ACMEClient

		for _, cfg := range group {
			if !HostQualifies(cfg.Host) || existingCertAndKey(cfg.Host) {
				continue
			}

			// Now we definitely do need a client
			if client == nil {
				var err error
				client, err = NewACMEClient(email, allowPrompts)
				if err != nil {
					return errors.New("error creating client: " + err.Error())
				}
			}

			// c.Configure assumes that allowPrompts == !proxyACME,
			// but that's not always true. For example, a restart where
			// the user isn't present and we're not listening on port 80.
			// TODO: This could probably be refactored better.
			if proxyACME {
				client.SetHTTPAddress(net.JoinHostPort(cfg.BindHost, AlternatePort))
				client.SetTLSAddress(net.JoinHostPort(cfg.BindHost, AlternatePort))
				client.ExcludeChallenges([]acme.Challenge{acme.TLSSNI01, acme.DNS01})
			} else {
				client.SetHTTPAddress(net.JoinHostPort(cfg.BindHost, ""))
				client.SetTLSAddress(net.JoinHostPort(cfg.BindHost, ""))
				client.ExcludeChallenges([]acme.Challenge{acme.DNS01})
			}

			err := client.Obtain([]string{cfg.Host})
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// groupConfigsByEmail groups configs by the email address to be used by an
// ACME client. It only groups configs that have TLS enabled and that are
// marked as Managed. If userPresent is true, the operator MAY be prompted
// for an email address.
func groupConfigsByEmail(configs []server.Config, userPresent bool) map[string][]server.Config {
	initMap := make(map[string][]server.Config)
	for _, cfg := range configs {
		if !cfg.TLS.Managed {
			continue
		}
		leEmail := getEmail(cfg, userPresent)
		initMap[leEmail] = append(initMap[leEmail], cfg)
	}
	return initMap
}

// EnableTLS configures each config to use TLS according to default settings.
// It will only change configs that are marked as managed, and assumes that
// certificates and keys are already on disk. If loadCertificates is true,
// the certificates will be loaded from disk into the cache for this process
// to use. If false, TLS will still be enabled and configured with default
// settings, but no certificates will be parsed loaded into the cache, and
// the returned error value will always be nil.
func EnableTLS(configs []server.Config, loadCertificates bool) error {
	for i := 0; i < len(configs); i++ {
		if !configs[i].TLS.Managed {
			continue
		}
		configs[i].TLS.Enabled = true
		if loadCertificates && HostQualifies(configs[i].Host) {
			_, err := cacheManagedCertificate(configs[i].Host, false)
			if err != nil {
				return err
			}
		}
		setDefaultTLSParams(&configs[i])
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
// fully managed TLS (but not on-demand TLS, which is
// not considered here). It does NOT check to see if a
// cert and key already exist for the config. If the
// config does qualify, you should set cfg.TLS.Managed
// to true and check that instead, because the process of
// setting up the config may make it look like it
// doesn't qualify even though it originally did.
func ConfigQualifies(cfg server.Config) bool {
	return (!cfg.TLS.Manual || cfg.TLS.OnDemand) && // user might provide own cert and key

		// user can force-disable automatic HTTPS for this host
		cfg.Scheme != "http" &&
		cfg.Port != "80" &&
		cfg.TLS.LetsEncryptEmail != "off" &&

		// we get can't certs for some kinds of hostnames, but
		// on-demand TLS allows empty hostnames at startup
		(HostQualifies(cfg.Host) || cfg.TLS.OnDemand)
}

// HostQualifies returns true if the hostname alone
// appears eligible for automatic HTTPS. For example,
// localhost, empty hostname, and IP addresses are
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
	toURL := "https://{host}" // serve any host, since cfg.Host could be empty
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
		Host:       cfg.Host,
		BindHost:   cfg.BindHost,
		Port:       "80",
		Middleware: []middleware.Middleware{redirMidware},
	}
}

// Revoke revokes the certificate for host via ACME protocol.
func Revoke(host string) error {
	if !existingCertAndKey(host) {
		return errors.New("no certificate and key for " + host)
	}

	email := getEmail(server.Config{Host: host}, true)
	if email == "" {
		return errors.New("email is required to revoke")
	}

	client, err := NewACMEClient(email, true)
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

// AlternatePort is the port on which the acme client will open a
// listener and solve the CA's challenges. If this alternate port
// is used instead of the default port (80 or 443), then the
// default port for the challenge must be forwarded to this one.
const AlternatePort = "5033"

// KeyType is the type to use for new keys.
// This shouldn't need to change except for in tests;
// the size can be drastically reduced for speed.
var KeyType = acme.EC384

// stopChan is used to signal the maintenance goroutine
// to terminate.
var stopChan chan struct{}
