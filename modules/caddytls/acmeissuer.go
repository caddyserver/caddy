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
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/url"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
	"github.com/go-acme/lego/v3/challenge"
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
	ExternalAccount *ExternalAccountBinding `json:"external_account,omitempty"`

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
	// DNS providers
	if m.Challenges != nil && m.Challenges.DNSRaw != nil {
		val, err := ctx.LoadModule(m.Challenges, "DNSRaw")
		if err != nil {
			return fmt.Errorf("loading DNS provider module: %v", err)
		}
		prov, err := val.(DNSProviderMaker).NewDNSProvider()
		if err != nil {
			return fmt.Errorf("making DNS provider: %v", err)
		}
		m.Challenges.DNS = prov
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
		Email:             m.Email,
		CertObtainTimeout: time.Duration(m.ACMETimeout),
		TrustedRoots:      m.rootPool,
	}

	if m.ExternalAccount != nil {
		hmac, err := base64.StdEncoding.DecodeString(m.ExternalAccount.EncodedHMAC)
		if err != nil {
			return template, err
		}
		if m.ExternalAccount.KeyID == "" || len(hmac) == 0 {
			return template, fmt.Errorf("when an external account binding is specified, both key ID and HMAC are required")
		}
		template.ExternalAccount = &certmagic.ExternalAccountBinding{
			KeyID: m.ExternalAccount.KeyID,
			HMAC:  hmac,
		}
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
		template.DNSProvider = m.Challenges.DNS
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
func (m *ACMEIssuer) PreCheck(names []string, interactive bool) error {
	return certmagic.NewACMEManager(m.magic, m.template).PreCheck(names, interactive)
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
func (m *ACMEIssuer) Revoke(ctx context.Context, cert certmagic.CertificateResource) error {
	return certmagic.NewACMEManager(m.magic, m.template).Revoke(ctx, cert)
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
		return fmt.Errorf("error checking %v to deterine if certificate for hostname '%s' should be allowed: %v",
			ask, name, err)
	}
	resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("certificate for hostname '%s' not allowed; non-2xx status code %d returned from %v",
			name, resp.StatusCode, ask)
	}

	return nil
}

// DNSProviderMaker is a type that can create a new DNS provider.
// Modules in the tls.dns namespace should implement this interface.
type DNSProviderMaker interface {
	NewDNSProvider() (challenge.Provider, error)
}

// ExternalAccountBinding contains information for
// binding an external account to an ACME account.
type ExternalAccountBinding struct {
	// The key identifier.
	KeyID string `json:"key_id,omitempty"`

	// The base64-encoded HMAC.
	EncodedHMAC string `json:"hmac,omitempty"`
}

// Interface guards
var (
	_ certmagic.PreChecker = (*ACMEIssuer)(nil)
	_ certmagic.Issuer     = (*ACMEIssuer)(nil)
	_ certmagic.Revoker    = (*ACMEIssuer)(nil)
	_ caddy.Provisioner    = (*ACMEIssuer)(nil)
	_ ConfigSetter         = (*ACMEIssuer)(nil)
)
