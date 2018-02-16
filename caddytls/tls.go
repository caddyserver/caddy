// Copyright 2015 Light Code Labs, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package caddytls facilitates the management of TLS assets and integrates
// Let's Encrypt functionality into Caddy with first-class support for
// creating and renewing certificates automatically. It also implements
// the tls directive.
//
// This package is meant to be used by Caddy server types. To use the
// tls directive, a server type must import this package and call
// RegisterConfigGetter(). The server type must make and keep track of
// the caddytls.Config structs that this package produces. It must also
// add tls to its list of directives. When it comes time to make the
// server instances, the server type can call MakeTLSConfig() to convert
// a []caddytls.Config to a single tls.Config for use in tls.NewListener().
// It is also recommended to call RotateSessionTicketKeys() when
// starting a new listener.
package caddytls

import (
	"encoding/json"
	"net"
	"strings"

	"github.com/mholt/caddy"
	"github.com/xenolf/lego/acme"
)

// HostQualifies returns true if the hostname alone
// appears eligible for automatic HTTPS. For example,
// localhost, empty hostname, and IP addresses are
// not eligible because we cannot obtain certificates
// for those names.
func HostQualifies(hostname string) bool {
	return hostname != "localhost" && // localhost is ineligible

		// hostname must not be empty
		strings.TrimSpace(hostname) != "" &&

		// must not contain wildcard (*) characters (until CA supports it)
		!strings.Contains(hostname, "*") &&

		// must not start or end with a dot
		!strings.HasPrefix(hostname, ".") &&
		!strings.HasSuffix(hostname, ".") &&

		// cannot be an IP address, see
		// https://community.letsencrypt.org/t/certificate-for-static-ip/84/2?u=mholt
		net.ParseIP(hostname) == nil
}

// saveCertResource saves the certificate resource to disk. This
// includes the certificate file itself, the private key, and the
// metadata file.
func saveCertResource(storage Storage, cert acme.CertificateResource) error {
	// Save cert, private key, and metadata
	siteData := &SiteData{
		Cert: cert.Certificate,
		Key:  cert.PrivateKey,
	}
	var err error
	siteData.Meta, err = json.MarshalIndent(&cert, "", "\t")
	if err == nil {
		err = storage.StoreSite(cert.Domain, siteData)
	}
	return err
}

// Revoke revokes the certificate for host via ACME protocol.
// It assumes the certificate was obtained from the
// CA at DefaultCAUrl.
func Revoke(host string) error {
	client, err := newACMEClient(new(Config), true)
	if err != nil {
		return err
	}
	return client.Revoke(host)
}

// tlsSNISolver is a type that can solve TLS-SNI challenges using
// an existing listener and our custom, in-memory certificate cache.
type tlsSNISolver struct {
	certCache *certificateCache
}

// Present adds the challenge certificate to the cache.
func (s tlsSNISolver) Present(domain, token, keyAuth string) error {
	cert, acmeDomain, err := acme.TLSSNI01ChallengeCert(keyAuth)
	if err != nil {
		return err
	}
	certHash := hashCertificateChain(cert.Certificate)
	s.certCache.Lock()
	s.certCache.cache[acmeDomain] = Certificate{
		Certificate: cert,
		Names:       []string{acmeDomain},
		Hash:        certHash, // perhaps not necesssary
	}
	s.certCache.Unlock()
	return nil
}

// CleanUp removes the challenge certificate from the cache.
func (s tlsSNISolver) CleanUp(domain, token, keyAuth string) error {
	_, acmeDomain, err := acme.TLSSNI01ChallengeCert(keyAuth)
	if err != nil {
		return err
	}
	s.certCache.Lock()
	delete(s.certCache.cache, acmeDomain)
	s.certCache.Unlock()
	return nil
}

// ConfigHolder is any type that has a Config; it presumably is
// connected to a hostname and port on which it is serving.
type ConfigHolder interface {
	TLSConfig() *Config
	Host() string
	Port() string
}

// QualifiesForManagedTLS returns true if c qualifies for
// for managed TLS (but not on-demand TLS specifically).
// It does NOT check to see if a cert and key already exist
// for the config. If the return value is true, you should
// be OK to set c.TLSConfig().Managed to true; then you should
// check that value in the future instead, because the process
// of setting up the config may make it look like it doesn't
// qualify even though it originally did.
func QualifiesForManagedTLS(c ConfigHolder) bool {
	if c == nil {
		return false
	}
	tlsConfig := c.TLSConfig()
	if tlsConfig == nil {
		return false
	}

	return (!tlsConfig.Manual || tlsConfig.OnDemand) && // user might provide own cert and key

		// if self-signed, we've already generated one to use
		!tlsConfig.SelfSigned &&

		// user can force-disable managed TLS
		c.Port() != "80" &&
		tlsConfig.ACMEEmail != "off" &&

		// we get can't certs for some kinds of hostnames, but
		// on-demand TLS allows empty hostnames at startup
		(HostQualifies(c.Host()) || tlsConfig.OnDemand)
}

// ChallengeProvider defines an own type that should be used in Caddy plugins
// over acme.ChallengeProvider. Using acme.ChallengeProvider causes version mismatches
// with vendored dependencies (see https://github.com/mattfarina/golang-broken-vendor)
//
// acme.ChallengeProvider is an interface that allows the implementation of custom
// challenge providers. For more details, see:
// https://godoc.org/github.com/xenolf/lego/acme#ChallengeProvider
type ChallengeProvider acme.ChallengeProvider

// DNSProviderConstructor is a function that takes credentials and
// returns a type that can solve the ACME DNS challenges.
type DNSProviderConstructor func(credentials ...string) (ChallengeProvider, error)

// dnsProviders is the list of DNS providers that have been plugged in.
var dnsProviders = make(map[string]DNSProviderConstructor)

// RegisterDNSProvider registers provider by name for solving the ACME DNS challenge.
func RegisterDNSProvider(name string, provider DNSProviderConstructor) {
	dnsProviders[name] = provider
	caddy.RegisterPlugin("tls.dns."+name, caddy.Plugin{})
}

var (
	// DefaultEmail represents the Let's Encrypt account email to use if none provided.
	DefaultEmail string

	// Agreed indicates whether user has agreed to the Let's Encrypt SA.
	Agreed bool

	// DefaultCAUrl is the default URL to the CA's ACME directory endpoint.
	// It's very important to set this unless you set it in every Config.
	DefaultCAUrl string

	// DefaultKeyType is used as the type of key for new certificates
	// when no other key type is specified.
	DefaultKeyType = acme.RSA2048

	// DisableHTTPChallenge will disable all HTTP challenges.
	DisableHTTPChallenge bool

	// DisableTLSSNIChallenge will disable all TLS-SNI challenges.
	DisableTLSSNIChallenge bool
)

var storageProviders = make(map[string]StorageConstructor)

// RegisterStorageProvider registers provider by name for storing tls data
func RegisterStorageProvider(name string, provider StorageConstructor) {
	storageProviders[name] = provider
	caddy.RegisterPlugin("tls.storage."+name, caddy.Plugin{})
}
