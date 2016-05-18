// Package caddytls facilitates the management of TLS assets and integrates
// Let's Encrypt functionality into Caddy with first-class support for
// creating and renewing certificates automatically.
// TODO: Move out of "shared" folder into top level of repo
package caddytls

// Deactivate cleans up long-term, in-memory resources
import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net"
	"os"
	"strings"

	"github.com/xenolf/lego/acme"
)

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

// CertObtainInfo is a type which can get the information needed
// to obtain TLS certificates via ACME.
type CertObtainInfo interface {
	// Key returns the key/name of the TLS config to use to obtain
	// certificates.
	Key() string

	// Host returns the hostname for which to obtain a certificate.
	Host() string

	// ListenerHost returns the host to listen on, if a listener
	// must be started. The port will be decided... separately I guess. TODO
	ListenerHost() string
}

// ObtainCert obtains a certificate for the hostname represented by info,
// as long as a certificate does not already exist in storage on disk. It
// only obtains and stores certificates (and their keys) to disk, it does
// not load them into memory. If allowPrompts is true, the user may be
// shown a prompt. If proxyACME is true, the relevant ACME challenges will
// be proxied to the alternate port.
// TODO - this function needs proxyACME to work, with custom alt port.
func ObtainCert(cfg *Config, allowPrompts, proxyACME bool) error {
	if !cfg.Managed || !HostQualifies(cfg.Hostname) || existingCertAndKey(cfg.Hostname) {
		return nil
	}

	if cfg.LetsEncryptEmail == "" {
		cfg.LetsEncryptEmail = getEmail(allowPrompts)
	}

	client, err := newACMEClient(cfg, allowPrompts)
	if err != nil {
		return err
	}

	// TODO: DNS providers should be plugins too, so we don't
	// have to import them all, right??
	/*
		var dnsProv acme.ChallengeProvider
		var err error
		switch cfg.DNSProvider {
		case "cloudflare":
			dnsProv, err = cloudflare.NewDNSProvider()
		case "digitalocean":
			dnsProv, err = digitalocean.NewDNSProvider()
		case "dnsimple":
			dnsProv, err = dnsimple.NewDNSProvider()
		case "dyn":
			dnsProv, err = dyn.NewDNSProvider()
		case "gandi":
			dnsProv, err = gandi.NewDNSProvider()
		case "gcloud":
			dnsProv, err = gcloud.NewDNSProvider()
		case "namecheap":
			dnsProv, err = namecheap.NewDNSProvider()
		case "rfc2136":
			dnsProv, err = rfc2136.NewDNSProvider()
		case "route53":
			dnsProv, err = route53.NewDNSProvider()
		case "vultr":
			dnsProv, err = vultr.NewDNSProvider()
		}
		if err != nil {
			return err
		}
		if dnsProv != nil {
			client.SetChallengeProvider(acme.DNS01, dnsProv)
		}
	*/

	// client.Configure() assumes that allowPrompts == !proxyACME,
	// but that's not always true. For example, a restart where
	// the user isn't present and we're not listening on port 80.
	// So we don't call client.Configure() here...
	// TODO: This is the "old" way of doing it; this needs work still...
	if proxyACME {
		client.SetHTTPAddress(net.JoinHostPort(cfg.ACMEHost, cfg.ACMEPort))
		client.SetTLSAddress(net.JoinHostPort(cfg.ACMEHost, cfg.ACMEPort))
		//client.ExcludeChallenges([]acme.Challenge{acme.TLSSNI01, acme.DNS01})
	} else {
		client.SetHTTPAddress(net.JoinHostPort(cfg.ACMEHost, cfg.ACMEPort))
		client.SetTLSAddress(net.JoinHostPort(cfg.ACMEHost, cfg.ACMEPort))
		//client.ExcludeChallenges([]acme.Challenge{acme.DNS01})
	}

	return client.Obtain([]string{cfg.Hostname})
}

func (c *Config) RenewCert(name string) error {
	client, err := newACMEClient(&Config{}, false)
	if err != nil {
		return err
	}
	return client.Renew(name)
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
		// TODO: Is the special case with [] still true?
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

// Revoke revokes the certificate for host via ACME protocol.
func Revoke(host string) error {
	if !existingCertAndKey(host) {
		return errors.New("no certificate and key for " + host)
	}

	// TODO: Use actual config?
	// TODO: Get email properly
	client, err := newACMEClient(&Config{}, true)
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

// tlsSniSolver is a type that can solve tls-sni challenges using
// an existing listener.
type tlsSniSolver struct{}

// Present adds the challenge certificate to the cache.
func (s tlsSniSolver) Present(domain, token, keyAuth string) error {
	cert, err := acme.TLSSNI01ChallengeCert(keyAuth)
	if err != nil {
		return err
	}
	cacheCertificate(Certificate{
		Certificate: cert,
		Names:       []string{domain},
	})
	return nil
}

// Cleanup removes the challenge certificate from the cache.
func (s tlsSniSolver) Cleanup(domain, token, keyAuth string) error {
	uncacheCertificate(domain)
	return nil
}

type ConfigHolder interface {
	TLSConfig() *Config
	Host() string
	Port() string
}

// QualifiesForManagedTLS returns true if c qualifies for
// for managed TLS (but not on-demand TLS specifically).
// It does NOT check to see if a cert and key already exist
// for the config. If the return value is true, you should
// be OK to set cfg.TLS.Managed to true; then you should check
// that value in the future instead, because the process of
// setting up the config may make it look like it doesn't
// qualify even though it originally did.
func QualifiesForManagedTLS(c ConfigHolder) bool {
	if c == nil {
		return false
	}
	tlsConfig := c.TLSConfig()

	return (!tlsConfig.Manual || tlsConfig.OnDemand) && // user might provide own cert and key

		// if self-signed, we've already generated one to use
		!tlsConfig.SelfSigned &&

		// user can force-disable managed TLS at a TLS level
		c.Port() != "80" &&
		tlsConfig.LetsEncryptEmail != "off" &&

		// we get can't certs for some kinds of hostnames, but
		// on-demand TLS allows empty hostnames at startup
		(HostQualifies(c.Host()) || tlsConfig.OnDemand)
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

// stopChan is used to signal the maintenance goroutine
// to terminate.
var stopChan chan struct{}
