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
// the tls directive. It's mostly powered by the CertMagic package.
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
	"github.com/go-acme/lego/challenge"
	"github.com/mholt/caddy"
	"github.com/mholt/certmagic"
)

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
	if tlsConfig == nil || tlsConfig.Manager == nil {
		return false
	}
	onDemand := tlsConfig.Manager.OnDemand != nil

	return (!tlsConfig.Manual || onDemand) && // user might provide own cert and key

		// if self-signed, we've already generated one to use
		!tlsConfig.SelfSigned &&

		// user can force-disable managed TLS
		c.Port() != "80" &&
		tlsConfig.ACMEEmail != "off" &&

		// we get can't certs for some kinds of hostnames, but
		// on-demand TLS allows empty hostnames at startup
		(certmagic.HostQualifies(c.Host()) || onDemand)
}

// Revoke revokes the certificate fro host via the ACME protocol.
// It assumes the certificate was obtained from certmagic.CA.
func Revoke(domainName string) error {
	return certmagic.NewDefault().RevokeCert(domainName, true)
}

// KnownACMECAs is a list of ACME directory endpoints of
// known, public, and trusted ACME-compatible certificate
// authorities.
var KnownACMECAs = []string{
	"https://acme-v02.api.letsencrypt.org/directory",
}

// ChallengeProvider defines an own type that should be used in Caddy plugins
// over challenge.Provider. Using challenge.Provider causes version mismatches
// with vendored dependencies (see https://github.com/mattfarina/golang-broken-vendor)
//
// challenge.Provider is an interface that allows the implementation of custom
// challenge providers. For more details, see:
// https://godoc.org/github.com/go-acme/lego/acme#ChallengeProvider
type ChallengeProvider challenge.Provider

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

// ClusterPluginConstructor is a function type that is used to
// instantiate a new implementation of both certmagic.Storage
// and certmagic.Locker, which are required for successful
// use in cluster environments.
type ClusterPluginConstructor func() (certmagic.Storage, error)

// clusterProviders is the list of storage providers
var clusterProviders = make(map[string]ClusterPluginConstructor)

// RegisterClusterPlugin registers provider by name for facilitating
// cluster-wide operations like storage and synchronization.
func RegisterClusterPlugin(name string, provider ClusterPluginConstructor) {
	clusterProviders[name] = provider
	caddy.RegisterPlugin("tls.cluster."+name, caddy.Plugin{})
}
