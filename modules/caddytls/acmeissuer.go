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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez"
	"github.com/mholt/acmez/acme"
	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func init() {
	caddy.RegisterModule(ACMEIssuer{})
}

// ACMEIssuer manages certificates using the ACME protocol (RFC 8555).
type ACMEIssuer struct {
	// The URL to the CA's ACME directory endpoint. Default:
	// https://acme-v02.api.letsencrypt.org/directory
	CA string `json:"ca,omitempty"`

	// The URL to the test CA's ACME directory endpoint.
	// This endpoint is only used during retries if there
	// is a failure using the primary CA. Default:
	// https://acme-staging-v02.api.letsencrypt.org/directory
	TestCA string `json:"test_ca,omitempty"`

	// Your email address, so the CA can contact you if necessary.
	// Not required, but strongly recommended to provide one so
	// you can be reached if there is a problem. Your email is
	// not sent to any Caddy mothership or used for any purpose
	// other than ACME transactions.
	Email string `json:"email,omitempty"`

	// If you have an existing account with the ACME server, put
	// the private key here in PEM format. The ACME client will
	// look up your account information with this key first before
	// trying to create a new one. You can use placeholders here,
	// for example if you have it in an environment variable.
	AccountKey string `json:"account_key,omitempty"`

	// If using an ACME CA that requires an external account
	// binding, specify the CA-provided credentials here.
	ExternalAccount *acme.EAB `json:"external_account,omitempty"`

	// Time to wait before timing out an ACME operation.
	// Default: 0 (no timeout)
	ACMETimeout caddy.Duration `json:"acme_timeout,omitempty"`

	// Configures the various ACME challenge types.
	Challenges *ChallengesConfig `json:"challenges,omitempty"`

	// An array of files of CA certificates to accept when connecting to the
	// ACME CA. Generally, you should only use this if the ACME CA endpoint
	// is internal or for development/testing purposes.
	TrustedRootsPEMFiles []string `json:"trusted_roots_pem_files,omitempty"`

	// Preferences for selecting alternate certificate chains, if offered
	// by the CA. By default, the first offered chain will be selected.
	// If configured, the chains may be sorted and the first matching chain
	// will be selected.
	PreferredChains *ChainPreference `json:"preferred_chains,omitempty"`

	rootPool *x509.CertPool
	logger   *zap.Logger

	template certmagic.ACMEIssuer  // set at Provision
	magic    *certmagic.Config     // set at PreCheck
	issuer   *certmagic.ACMEIssuer // set at PreCheck; result of template + magic
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
	iss.logger = ctx.Logger()

	repl := caddy.NewReplacer()

	// expand email address, if non-empty
	if iss.Email != "" {
		email, err := repl.ReplaceOrErr(iss.Email, true, true)
		if err != nil {
			return fmt.Errorf("expanding email address '%s': %v", iss.Email, err)
		}
		iss.Email = email
	}

	// expand account key, if non-empty
	if iss.AccountKey != "" {
		accountKey, err := repl.ReplaceOrErr(iss.AccountKey, true, true)
		if err != nil {
			return fmt.Errorf("expanding account key PEM '%s': %v", iss.AccountKey, err)
		}
		iss.AccountKey = accountKey
	}

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
				PropagationDelay:   time.Duration(iss.Challenges.DNS.PropagationDelay),
				PropagationTimeout: time.Duration(iss.Challenges.DNS.PropagationTimeout),
				Resolvers:          iss.Challenges.DNS.Resolvers,
				OverrideDomain:     iss.Challenges.DNS.OverrideDomain,
			}
		}
	}

	// add any custom CAs to trust store
	if len(iss.TrustedRootsPEMFiles) > 0 {
		iss.rootPool = x509.NewCertPool()
		for _, pemFile := range iss.TrustedRootsPEMFiles {
			pemData, err := os.ReadFile(pemFile)
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

func (iss *ACMEIssuer) makeIssuerTemplate() (certmagic.ACMEIssuer, error) {
	template := certmagic.ACMEIssuer{
		CA:                iss.CA,
		TestCA:            iss.TestCA,
		Email:             iss.Email,
		AccountKeyPEM:     iss.AccountKey,
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

	if iss.PreferredChains != nil {
		template.PreferredChains = certmagic.ChainPreference{
			Smallest:       iss.PreferredChains.Smallest,
			AnyCommonName:  iss.PreferredChains.AnyCommonName,
			RootCommonName: iss.PreferredChains.RootCommonName,
		}
	}

	return template, nil
}

// SetConfig sets the associated certmagic config for this issuer.
// This is required because ACME needs values from the config in
// order to solve the challenges during issuance. This implements
// the ConfigSetter interface.
func (iss *ACMEIssuer) SetConfig(cfg *certmagic.Config) {
	iss.magic = cfg
	iss.issuer = certmagic.NewACMEIssuer(cfg, iss.template)
}

// PreCheck implements the certmagic.PreChecker interface.
func (iss *ACMEIssuer) PreCheck(ctx context.Context, names []string, interactive bool) error {
	return iss.issuer.PreCheck(ctx, names, interactive)
}

// Issue obtains a certificate for the given csr.
func (iss *ACMEIssuer) Issue(ctx context.Context, csr *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	return iss.issuer.Issue(ctx, csr)
}

// IssuerKey returns the unique issuer key for the configured CA endpoint.
func (iss *ACMEIssuer) IssuerKey() string {
	return iss.issuer.IssuerKey()
}

// Revoke revokes the given certificate.
func (iss *ACMEIssuer) Revoke(ctx context.Context, cert certmagic.CertificateResource, reason int) error {
	return iss.issuer.Revoke(ctx, cert, reason)
}

// GetACMEIssuer returns iss. This is useful when other types embed ACMEIssuer, because
// type-asserting them to *ACMEIssuer will fail, but type-asserting them to an interface
// with only this method will succeed, and will still allow the embedded ACMEIssuer
// to be accessed and manipulated.
func (iss *ACMEIssuer) GetACMEIssuer() *ACMEIssuer { return iss }

// UnmarshalCaddyfile deserializes Caddyfile tokens into iss.
//
//	... acme [<directory_url>] {
//	    dir <directory_url>
//	    test_dir <test_directory_url>
//	    email <email>
//	    timeout <duration>
//	    disable_http_challenge
//	    disable_tlsalpn_challenge
//	    alt_http_port    <port>
//	    alt_tlsalpn_port <port>
//	    eab <key_id> <mac_key>
//	    trusted_roots <pem_files...>
//	    dns <provider_name> [<options>]
//	    propagation_delay <duration>
//	    propagation_timeout <duration>
//	    resolvers <dns_servers...>
//	    dns_ttl <duration>
//	    dns_challenge_override_domain <domain>
//	    preferred_chains [smallest] {
//	        root_common_name <common_names...>
//	        any_common_name  <common_names...>
//	    }
//	}
func (iss *ACMEIssuer) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			iss.CA = d.Val()
			if d.NextArg() {
				return d.ArgErr()
			}
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "dir":
				if iss.CA != "" {
					return d.Errf("directory is already specified: %s", iss.CA)
				}
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
				unm, err := caddyfile.UnmarshalModule(d, "dns.providers."+provName)
				if err != nil {
					return err
				}
				iss.Challenges.DNS.ProviderRaw = caddyconfig.JSONModuleObject(unm, "name", provName, nil)

			case "propagation_delay":
				if !d.NextArg() {
					return d.ArgErr()
				}
				delayStr := d.Val()
				delay, err := caddy.ParseDuration(delayStr)
				if err != nil {
					return d.Errf("invalid propagation_delay duration %s: %v", delayStr, err)
				}
				if iss.Challenges == nil {
					iss.Challenges = new(ChallengesConfig)
				}
				if iss.Challenges.DNS == nil {
					iss.Challenges.DNS = new(DNSChallengeConfig)
				}
				iss.Challenges.DNS.PropagationDelay = caddy.Duration(delay)

			case "propagation_timeout":
				if !d.NextArg() {
					return d.ArgErr()
				}
				timeoutStr := d.Val()
				var timeout time.Duration
				if timeoutStr == "-1" {
					timeout = time.Duration(-1)
				} else {
					var err error
					timeout, err = caddy.ParseDuration(timeoutStr)
					if err != nil {
						return d.Errf("invalid propagation_timeout duration %s: %v", timeoutStr, err)
					}
				}
				if iss.Challenges == nil {
					iss.Challenges = new(ChallengesConfig)
				}
				if iss.Challenges.DNS == nil {
					iss.Challenges.DNS = new(DNSChallengeConfig)
				}
				iss.Challenges.DNS.PropagationTimeout = caddy.Duration(timeout)

			case "resolvers":
				if iss.Challenges == nil {
					iss.Challenges = new(ChallengesConfig)
				}
				if iss.Challenges.DNS == nil {
					iss.Challenges.DNS = new(DNSChallengeConfig)
				}
				iss.Challenges.DNS.Resolvers = d.RemainingArgs()
				if len(iss.Challenges.DNS.Resolvers) == 0 {
					return d.ArgErr()
				}

			case "dns_ttl":
				if !d.NextArg() {
					return d.ArgErr()
				}
				ttlStr := d.Val()
				ttl, err := caddy.ParseDuration(ttlStr)
				if err != nil {
					return d.Errf("invalid dns_ttl duration %s: %v", ttlStr, err)
				}
				if iss.Challenges == nil {
					iss.Challenges = new(ChallengesConfig)
				}
				if iss.Challenges.DNS == nil {
					iss.Challenges.DNS = new(DNSChallengeConfig)
				}
				iss.Challenges.DNS.TTL = caddy.Duration(ttl)

			case "dns_challenge_override_domain":
				arg := d.RemainingArgs()
				if len(arg) != 1 {
					return d.ArgErr()
				}
				if iss.Challenges == nil {
					iss.Challenges = new(ChallengesConfig)
				}
				if iss.Challenges.DNS == nil {
					iss.Challenges.DNS = new(DNSChallengeConfig)
				}
				iss.Challenges.DNS.OverrideDomain = arg[0]

			case "preferred_chains":
				chainPref, err := ParseCaddyfilePreferredChainsOptions(d)
				if err != nil {
					return err
				}
				iss.PreferredChains = chainPref

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
func onDemandAskRequest(ctx context.Context, logger *zap.Logger, ask string, name string) error {
	askURL, err := url.Parse(ask)
	if err != nil {
		return fmt.Errorf("parsing ask URL: %v", err)
	}
	qs := askURL.Query()
	qs.Set("domain", name)
	askURL.RawQuery = qs.Encode()

	askURLString := askURL.String()
	resp, err := onDemandAskClient.Get(askURLString)
	if err != nil {
		return fmt.Errorf("error checking %v to determine if certificate for hostname '%s' should be allowed: %v",
			ask, name, err)
	}
	resp.Body.Close()

	// logging out the client IP can be useful for servers that want to count
	// attempts from clients to detect patterns of abuse
	var clientIP string
	if hello, ok := ctx.Value(certmagic.ClientHelloInfoCtxKey).(*tls.ClientHelloInfo); ok && hello != nil {
		if remote := hello.Conn.RemoteAddr(); remote != nil {
			clientIP, _, _ = net.SplitHostPort(remote.String())
		}
	}

	logger.Debug("response from ask endpoint",
		zap.String("client_ip", clientIP),
		zap.String("domain", name),
		zap.String("url", askURLString),
		zap.Int("status", resp.StatusCode))

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%s: %w %s - non-2xx status code %d", name, errAskDenied, ask, resp.StatusCode)
	}

	return nil
}

func ParseCaddyfilePreferredChainsOptions(d *caddyfile.Dispenser) (*ChainPreference, error) {
	chainPref := new(ChainPreference)
	if d.NextArg() {
		smallestOpt := d.Val()
		if smallestOpt == "smallest" {
			trueBool := true
			chainPref.Smallest = &trueBool
			if d.NextArg() { // Only one argument allowed
				return nil, d.ArgErr()
			}
			if d.NextBlock(d.Nesting()) { // Don't allow other options when smallest == true
				return nil, d.Err("No more options are accepted when using the 'smallest' option")
			}
		} else { // Smallest option should always be 'smallest' or unset
			return nil, d.Errf("Invalid argument '%s'", smallestOpt)
		}
	}
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "root_common_name":
			rootCommonNameOpt := d.RemainingArgs()
			chainPref.RootCommonName = rootCommonNameOpt
			if rootCommonNameOpt == nil {
				return nil, d.ArgErr()
			}
			if chainPref.AnyCommonName != nil {
				return nil, d.Err("Can't set root_common_name when any_common_name is already set")
			}

		case "any_common_name":
			anyCommonNameOpt := d.RemainingArgs()
			chainPref.AnyCommonName = anyCommonNameOpt
			if anyCommonNameOpt == nil {
				return nil, d.ArgErr()
			}
			if chainPref.RootCommonName != nil {
				return nil, d.Err("Can't set any_common_name when root_common_name is already set")
			}

		default:
			return nil, d.Errf("Received unrecognized parameter '%s'", d.Val())
		}
	}

	if chainPref.Smallest == nil && chainPref.RootCommonName == nil && chainPref.AnyCommonName == nil {
		return nil, d.Err("No options for preferred_chains received")
	}

	return chainPref, nil
}

// ChainPreference describes the client's preferred certificate chain,
// useful if the CA offers alternate chains. The first matching chain
// will be selected.
type ChainPreference struct {
	// Prefer chains with the fewest number of bytes.
	Smallest *bool `json:"smallest,omitempty"`

	// Select first chain having a root with one of
	// these common names.
	RootCommonName []string `json:"root_common_name,omitempty"`

	// Select first chain that has any issuer with one
	// of these common names.
	AnyCommonName []string `json:"any_common_name,omitempty"`
}

// errAskDenied is an error that should be wrapped or returned when the
// configured "ask" endpoint does not allow a certificate to be issued,
// to distinguish that from other errors such as connection failure.
var errAskDenied = errors.New("certificate not allowed by ask endpoint")

// Interface guards
var (
	_ certmagic.PreChecker  = (*ACMEIssuer)(nil)
	_ certmagic.Issuer      = (*ACMEIssuer)(nil)
	_ certmagic.Revoker     = (*ACMEIssuer)(nil)
	_ caddy.Provisioner     = (*ACMEIssuer)(nil)
	_ ConfigSetter          = (*ACMEIssuer)(nil)
	_ caddyfile.Unmarshaler = (*ACMEIssuer)(nil)
)
