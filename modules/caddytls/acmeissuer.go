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
	"strconv"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
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

// Provision sets up iss.
func (iss *ACMEIssuer) Provision(ctx caddy.Context) error {
	iss.logger = ctx.Logger(iss)

	// DNS providers
	if iss.Challenges != nil && iss.Challenges.DNS != nil && iss.Challenges.DNS.ProviderRaw != nil {
		val, err := ctx.LoadModule(iss.Challenges.DNS, "ProviderRaw")
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
			iss.Challenges.DNS.solver = deprecatedProvider
		} else {
			iss.Challenges.DNS.solver = &certmagic.DNS01Solver{
				DNSProvider:        val.(certmagic.ACMEDNSProvider),
				TTL:                time.Duration(iss.Challenges.DNS.TTL),
				PropagationTimeout: time.Duration(iss.Challenges.DNS.PropagationTimeout),
				Resolvers:          iss.Challenges.DNS.Resolvers,
			}
		}
	}

	// add any custom CAs to trust store
	if len(iss.TrustedRootsPEMFiles) > 0 {
		iss.rootPool = x509.NewCertPool()
		for _, pemFile := range iss.TrustedRootsPEMFiles {
			pemData, err := ioutil.ReadFile(pemFile)
			if err != nil {
				return fmt.Errorf("loading trusted root CA's PEM file: %s: %v", pemFile, err)
			}
			if !iss.rootPool.AppendCertsFromPEM(pemData) {
				return fmt.Errorf("unable to add %s to trust pool: %v", pemFile, err)
			}
		}
	}

	var err error
	iss.template, err = iss.makeIssuerTemplate()
	if err != nil {
		return err
	}

	return nil
}

func (iss *ACMEIssuer) makeIssuerTemplate() (certmagic.ACMEManager, error) {
	template := certmagic.ACMEManager{
		CA:                iss.CA,
		TestCA:            iss.TestCA,
		Email:             iss.Email,
		CertObtainTimeout: time.Duration(iss.ACMETimeout),
		TrustedRoots:      iss.rootPool,
		ExternalAccount:   iss.ExternalAccount,
		Logger:            iss.logger,
	}

	if iss.Challenges != nil {
		if iss.Challenges.HTTP != nil {
			template.DisableHTTPChallenge = iss.Challenges.HTTP.Disabled
			template.AltHTTPPort = iss.Challenges.HTTP.AlternatePort
		}
		if iss.Challenges.TLSALPN != nil {
			template.DisableTLSALPNChallenge = iss.Challenges.TLSALPN.Disabled
			template.AltTLSALPNPort = iss.Challenges.TLSALPN.AlternatePort
		}
		if iss.Challenges.DNS != nil {
			template.DNS01Solver = iss.Challenges.DNS.solver
		}
		template.ListenHost = iss.Challenges.BindHost
	}

	return template, nil
}

// SetConfig sets the associated certmagic config for this issuer.
// This is required because ACME needs values from the config in
// order to solve the challenges during issuance. This implements
// the ConfigSetter interface.
func (iss *ACMEIssuer) SetConfig(cfg *certmagic.Config) {
	iss.magic = cfg
}

// TODO: I kind of hate how each call to these methods needs to
// make a new ACME manager to fill in defaults before using; can
// we find the right place to do that just once and then re-use?

// PreCheck implements the certmagic.PreChecker interface.
func (iss *ACMEIssuer) PreCheck(ctx context.Context, names []string, interactive bool) error {
	return certmagic.NewACMEManager(iss.magic, iss.template).PreCheck(ctx, names, interactive)
}

// Issue obtains a certificate for the given csr.
func (iss *ACMEIssuer) Issue(ctx context.Context, csr *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	return certmagic.NewACMEManager(iss.magic, iss.template).Issue(ctx, csr)
}

// IssuerKey returns the unique issuer key for the configured CA endpoint.
func (iss *ACMEIssuer) IssuerKey() string {
	return certmagic.NewACMEManager(iss.magic, iss.template).IssuerKey()
}

// Revoke revokes the given certificate.
func (iss *ACMEIssuer) Revoke(ctx context.Context, cert certmagic.CertificateResource, reason int) error {
	return certmagic.NewACMEManager(iss.magic, iss.template).Revoke(ctx, cert, reason)
}

// GetACMEIssuer returns iss. This is useful when other types embed ACMEIssuer, because
// type-asserting them to *ACMEIssuer will fail, but type-asserting them to an interface
// with only this method will succeed, and will still allow the embedded ACMEIssuer
// to be accessed and manipulated.
func (iss *ACMEIssuer) GetACMEIssuer() *ACMEIssuer { return iss }

// UnmarshalCaddyfile deserializes Caddyfile tokens into iss.
//
//     ... acme {
//         dir <directory_url>
//         test_dir <test_directory_url>
//         email <email>
//         timeout <duration>
//         disable_http_challenge
//         disable_tlsalpn_challenge
//         alt_http_port    <port>
//         alt_tlsalpn_port <port>
//         eab <key_id> <mac_key>
//         trusted_roots <pem_files...>
//         dns <provider_name> [<options>]
//         resolvers <dns_servers...>
//     }
//
func (iss *ACMEIssuer) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "dir":
				if !d.AllArgs(&iss.CA) {
					return d.ArgErr()
				}

			case "test_dir":
				if !d.AllArgs(&iss.TestCA) {
					return d.ArgErr()
				}

			case "email":
				if !d.AllArgs(&iss.Email) {
					return d.ArgErr()
				}

			case "timeout":
				var timeoutStr string
				if !d.AllArgs(&timeoutStr) {
					return d.ArgErr()
				}
				timeout, err := caddy.ParseDuration(timeoutStr)
				if err != nil {
					return d.Errf("invalid timeout duration %s: %v", timeoutStr, err)
				}
				iss.ACMETimeout = caddy.Duration(timeout)

			case "disable_http_challenge":
				if d.NextArg() {
					return d.ArgErr()
				}
				if iss.Challenges == nil {
					iss.Challenges = new(ChallengesConfig)
				}
				if iss.Challenges.HTTP == nil {
					iss.Challenges.HTTP = new(HTTPChallengeConfig)
				}
				iss.Challenges.HTTP.Disabled = true

			case "disable_tlsalpn_challenge":
				if d.NextArg() {
					return d.ArgErr()
				}
				if iss.Challenges == nil {
					iss.Challenges = new(ChallengesConfig)
				}
				if iss.Challenges.TLSALPN == nil {
					iss.Challenges.TLSALPN = new(TLSALPNChallengeConfig)
				}
				iss.Challenges.TLSALPN.Disabled = true

			case "alt_http_port":
				if !d.NextArg() {
					return d.ArgErr()
				}
				port, err := strconv.Atoi(d.Val())
				if err != nil {
					return d.Errf("invalid port %s: %v", d.Val(), err)
				}
				if iss.Challenges == nil {
					iss.Challenges = new(ChallengesConfig)
				}
				if iss.Challenges.HTTP == nil {
					iss.Challenges.HTTP = new(HTTPChallengeConfig)
				}
				iss.Challenges.HTTP.AlternatePort = port

			case "alt_tlsalpn_port":
				if !d.NextArg() {
					return d.ArgErr()
				}
				port, err := strconv.Atoi(d.Val())
				if err != nil {
					return d.Errf("invalid port %s: %v", d.Val(), err)
				}
				if iss.Challenges == nil {
					iss.Challenges = new(ChallengesConfig)
				}
				if iss.Challenges.TLSALPN == nil {
					iss.Challenges.TLSALPN = new(TLSALPNChallengeConfig)
				}
				iss.Challenges.TLSALPN.AlternatePort = port

			case "eab":
				iss.ExternalAccount = new(acme.EAB)
				if !d.AllArgs(&iss.ExternalAccount.KeyID, &iss.ExternalAccount.MACKey) {
					return d.ArgErr()
				}

			case "trusted_roots":
				iss.TrustedRootsPEMFiles = d.RemainingArgs()

			case "dns":
				if !d.NextArg() {
					return d.ArgErr()
				}
				provName := d.Val()
				if iss.Challenges == nil {
					iss.Challenges = new(ChallengesConfig)
				}
				if iss.Challenges.DNS == nil {
					iss.Challenges.DNS = new(DNSChallengeConfig)
				}
				dnsProvModule, err := caddy.GetModule("dns.providers." + provName)
				if err != nil {
					return d.Errf("getting DNS provider module named '%s': %v", provName, err)
				}
				dnsProvModuleInstance := dnsProvModule.New()
				if unm, ok := dnsProvModuleInstance.(caddyfile.Unmarshaler); ok {
					err = unm.UnmarshalCaddyfile(d.NewFromNextSegment())
					if err != nil {
						return err
					}
				}
				iss.Challenges.DNS.ProviderRaw = caddyconfig.JSONModuleObject(dnsProvModuleInstance, "name", provName, nil)

			case "resolvers":
				if !d.NextArg() {
					return d.ArgErr()
				}
				if iss.Challenges == nil {
					iss.Challenges = new(ChallengesConfig)
				}
				if iss.Challenges.DNS == nil {
					iss.Challenges.DNS = new(DNSChallengeConfig)
				}
				iss.Challenges.DNS.Resolvers = d.RemainingArgs()

			default:
				return d.Errf("unrecognized ACME issuer property: %s", d.Val())
			}
		}
	}
	return nil
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
	_ certmagic.PreChecker  = (*ACMEIssuer)(nil)
	_ certmagic.Issuer      = (*ACMEIssuer)(nil)
	_ certmagic.Revoker     = (*ACMEIssuer)(nil)
	_ caddy.Provisioner     = (*ACMEIssuer)(nil)
	_ ConfigSetter          = (*ACMEIssuer)(nil)
	_ caddyfile.Unmarshaler = (*ACMEIssuer)(nil)
)
