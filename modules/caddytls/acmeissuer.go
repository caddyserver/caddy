// Copyright 2015 Matthew Holt and The Caddy Authors
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

package caddytls

import (
	"context"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/url"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez"
	"github.com/mholt/acmez/acme"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(ACMEIssuer{})
}

// ACMEIssuer makes an ACME manager
// for managing certificates using ACME.
//
// TODO: support multiple ACME endpoints (probably
// requires an array of these structs) - caddy would
// also have to load certs from the backup CAs if the
// first one is expired...
type ACMEIssuer struct {
	// The URL to the CA's ACME directory endpoint.
	CA string `json:"ca,omitempty"`

	// The URL to the test CA's ACME directory endpoint.
	// This endpoint is only used during retries if there
	// is a failure using the primary CA.
	TestCA string `json:"test_ca,omitempty"`

	// Your email address, so the CA can contact you if necessary.
	// Not required, but strongly recommended to provide one so
	// you can be reached if there is a problem. Your email is
	// not sent to any Caddy mothership or used for any purpose
	// other than ACME transactions.
	Email string `json:"email,omitempty"`

	// If using an ACME CA that requires an external account
	// binding, specify the CA-provided credentials here.
	ExternalAccount *acme.EAB `json:"external_account,omitempty"`

	// Time to wait before timing out an ACME operation.
	ACMETimeout caddy.Duration `json:"acme_timeout,omitempty"`

	// Configures the various ACME challenge types.
	Challenges *ChallengesConfig `json:"challenges,omitempty"`

	// An array of files of CA certificates to accept when connecting to the
	// ACME CA. Generally, you should only use this if the ACME CA endpoint
	// is internal or for development/testing purposes.
	TrustedRootsPEMFiles []string `json:"trusted_roots_pem_files,omitempty"`

	rootPool *x509.CertPool
	template certmagic.ACMEManager
	magic    *certmagic.Config
	logger   *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (ACMEIssuer) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.issuance.acme",
		New: func() caddy.Module { return new(ACMEIssuer) },
	}
}

// Provision sets up m.
func (m *ACMEIssuer) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)

	// DNS providers
	if m.Challenges != nil && m.Challenges.DNS != nil && m.Challenges.DNS.ProviderRaw != nil {
		val, err := ctx.LoadModule(m.Challenges.DNS, "ProviderRaw")
		if err != nil {
			return fmt.Errorf("loading DNS provider module: %v", err)
		}

		if deprecatedProvider, ok := val.(acmez.Solver); ok {
			// TODO: For a temporary amount of time, we are allowing the use of DNS
			// providers from go-acme/lego since there are so many providers implemented
			// using that API -- they are adapted as an all-in-one Caddy module in this
			// repository: https://github.com/caddy-dns/lego-deprecated - the module is a
			// acmez.Solver type, so we use it directly. The user must set environment
			// variables to configure it. Remove this shim once a sufficient number of
			// DNS providers are implemented for the libdns APIs instead.
			m.Challenges.DNS.solver = deprecatedProvider
		} else {
			m.Challenges.DNS.solver = &certmagic.DNS01Solver{
				DNSProvider:        val.(certmagic.ACMEDNSProvider),
				TTL:                time.Duration(m.Challenges.DNS.TTL),
				PropagationTimeout: time.Duration(m.Challenges.DNS.PropagationTimeout),
			}
		}
	}

	// add any custom CAs to trust store
	if len(m.TrustedRootsPEMFiles) > 0 {
		m.rootPool = x509.NewCertPool()
		for _, pemFile := range m.TrustedRootsPEMFiles {
			pemData, err := ioutil.ReadFile(pemFile)
			if err != nil {
				return fmt.Errorf("loading trusted root CA's PEM file: %s: %v", pemFile, err)
			}
			if !m.rootPool.AppendCertsFromPEM(pemData) {
				return fmt.Errorf("unable to add %s to trust pool: %v", pemFile, err)
			}
		}
	}

	var err error
	m.template, err = m.makeIssuerTemplate()
	if err != nil {
		return err
	}

	return nil
}

func (m *ACMEIssuer) makeIssuerTemplate() (certmagic.ACMEManager, error) {
	template := certmagic.ACMEManager{
		CA:                m.CA,
		TestCA:            m.TestCA,
		Email:             m.Email,
		CertObtainTimeout: time.Duration(m.ACMETimeout),
		TrustedRoots:      m.rootPool,
		ExternalAccount:   m.ExternalAccount,
		Logger:            m.logger,
	}

	if m.Challenges != nil {
		if m.Challenges.HTTP != nil {
			template.DisableHTTPChallenge = m.Challenges.HTTP.Disabled
			template.AltHTTPPort = m.Challenges.HTTP.AlternatePort
		}
		if m.Challenges.TLSALPN != nil {
			template.DisableTLSALPNChallenge = m.Challenges.TLSALPN.Disabled
			template.AltTLSALPNPort = m.Challenges.TLSALPN.AlternatePort
		}
		if m.Challenges.DNS != nil {
			template.DNS01Solver = m.Challenges.DNS.solver
		}
		template.ListenHost = m.Challenges.BindHost
	}

	return template, nil
}

// SetConfig sets the associated certmagic config for this issuer.
// This is required because ACME needs values from the config in
// order to solve the challenges during issuance. This implements
// the ConfigSetter interface.
func (m *ACMEIssuer) SetConfig(cfg *certmagic.Config) {
	m.magic = cfg
}

// TODO: I kind of hate how each call to these methods needs to
// make a new ACME manager to fill in defaults before using; can
// we find the right place to do that just once and then re-use?

// PreCheck implements the certmagic.PreChecker interface.
func (m *ACMEIssuer) PreCheck(ctx context.Context, names []string, interactive bool) error {
	return certmagic.NewACMEManager(m.magic, m.template).PreCheck(ctx, names, interactive)
}

// Issue obtains a certificate for the given csr.
func (m *ACMEIssuer) Issue(ctx context.Context, csr *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	return certmagic.NewACMEManager(m.magic, m.template).Issue(ctx, csr)
}

// IssuerKey returns the unique issuer key for the configured CA endpoint.
func (m *ACMEIssuer) IssuerKey() string {
	return certmagic.NewACMEManager(m.magic, m.template).IssuerKey()
}

// Revoke revokes the given certificate.
func (m *ACMEIssuer) Revoke(ctx context.Context, cert certmagic.CertificateResource, reason int) error {
	return certmagic.NewACMEManager(m.magic, m.template).Revoke(ctx, cert, reason)
}

// onDemandAskRequest makes a request to the ask URL
// to see if a certificate can be obtained for name.
// The certificate request should be denied if this
// returns an error.
func onDemandAskRequest(ask string, name string) error {
	askURL, err := url.Parse(ask)
	if err != nil {
		return fmt.Errorf("parsing ask URL: %v", err)
	}
	qs := askURL.Query()
	qs.Set("domain", name)
	askURL.RawQuery = qs.Encode()

	resp, err := onDemandAskClient.Get(askURL.String())
	if err != nil {
		return fmt.Errorf("error checking %v to determine if certificate for hostname '%s' should be allowed: %v",
			ask, name, err)
	}
	resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("certificate for hostname '%s' not allowed; non-2xx status code %d returned from %v",
			name, resp.StatusCode, ask)
	}

	return nil
}

// Interface guards
var (
	_ certmagic.PreChecker = (*ACMEIssuer)(nil)
	_ certmagic.Issuer     = (*ACMEIssuer)(nil)
	_ certmagic.Revoker    = (*ACMEIssuer)(nil)
	_ caddy.Provisioner    = (*ACMEIssuer)(nil)
	_ ConfigSetter         = (*ACMEIssuer)(nil)
)
