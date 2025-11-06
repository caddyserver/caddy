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
	"strconv"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func init() {
	caddy.RegisterModule(new(ZeroSSLIssuer))
}

// ZeroSSLIssuer uses the ZeroSSL API to get certificates.
// Note that this is distinct from ZeroSSL's ACME endpoint.
// To use ZeroSSL's ACME endpoint, use the ACMEIssuer
// configured with ZeroSSL's ACME directory endpoint.
type ZeroSSLIssuer struct {
	// The API key (or "access key") for using the ZeroSSL API.
	// REQUIRED.
	APIKey string `json:"api_key,omitempty"`

	// How many days the certificate should be valid for.
	// Only certain values are accepted; see ZeroSSL docs.
	ValidityDays int `json:"validity_days,omitempty"`

	// The host to bind to when opening a listener for
	// verifying domain names (or IPs).
	ListenHost string `json:"listen_host,omitempty"`

	// If HTTP is forwarded from port 80, specify the
	// forwarded port here.
	AlternateHTTPPort int `json:"alternate_http_port,omitempty"`

	// Use CNAME validation instead of HTTP. ZeroSSL's
	// API uses CNAME records for DNS validation, similar
	// to how Let's Encrypt uses TXT records for the
	// DNS challenge.
	CNAMEValidation *DNSChallengeConfig `json:"cname_validation,omitempty"`

	logger  *zap.Logger
	storage certmagic.Storage
	issuer  *certmagic.ZeroSSLIssuer
}

// CaddyModule returns the Caddy module information.
func (*ZeroSSLIssuer) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.issuance.zerossl",
		New: func() caddy.Module { return new(ZeroSSLIssuer) },
	}
}

// Provision sets up the issuer.
func (iss *ZeroSSLIssuer) Provision(ctx caddy.Context) error {
	iss.logger = ctx.Logger()
	iss.storage = ctx.Storage()
	repl := caddy.NewReplacer()

	var dnsManager *certmagic.DNSManager
	if iss.CNAMEValidation != nil && len(iss.CNAMEValidation.ProviderRaw) > 0 {
		val, err := ctx.LoadModule(iss.CNAMEValidation, "ProviderRaw")
		if err != nil {
			return fmt.Errorf("loading DNS provider module: %v", err)
		}
		dnsManager = &certmagic.DNSManager{
			DNSProvider:        val.(certmagic.DNSProvider),
			TTL:                time.Duration(iss.CNAMEValidation.TTL),
			PropagationDelay:   time.Duration(iss.CNAMEValidation.PropagationDelay),
			PropagationTimeout: time.Duration(iss.CNAMEValidation.PropagationTimeout),
			Resolvers:          iss.CNAMEValidation.Resolvers,
			OverrideDomain:     iss.CNAMEValidation.OverrideDomain,
			Logger:             iss.logger.Named("cname"),
		}
	}

	iss.issuer = &certmagic.ZeroSSLIssuer{
		APIKey:          repl.ReplaceAll(iss.APIKey, ""),
		ValidityDays:    iss.ValidityDays,
		ListenHost:      iss.ListenHost,
		AltHTTPPort:     iss.AlternateHTTPPort,
		Storage:         iss.storage,
		CNAMEValidation: dnsManager,
		Logger:          iss.logger,
	}

	return nil
}

// Issue obtains a certificate for the given csr.
func (iss *ZeroSSLIssuer) Issue(ctx context.Context, csr *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	return iss.issuer.Issue(ctx, csr)
}

// IssuerKey returns the unique issuer key for the configured CA endpoint.
func (iss *ZeroSSLIssuer) IssuerKey() string {
	return iss.issuer.IssuerKey()
}

// Revoke revokes the given certificate.
func (iss *ZeroSSLIssuer) Revoke(ctx context.Context, cert certmagic.CertificateResource, reason int) error {
	return iss.issuer.Revoke(ctx, cert, reason)
}

// UnmarshalCaddyfile deserializes Caddyfile tokens into iss.
//
//	... zerossl <api_key> {
//		    validity_days <days>
//		    alt_http_port <port>
//		    dns <provider_name> ...
//		    propagation_delay <duration>
//		    propagation_timeout <duration>
//		    resolvers <list...>
//		    dns_ttl <duration>
//	}
func (iss *ZeroSSLIssuer) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume issuer name

	// API key is required
	if !d.NextArg() {
		return d.ArgErr()
	}
	iss.APIKey = d.Val()
	if d.NextArg() {
		return d.ArgErr()
	}

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "validity_days":
			if iss.ValidityDays != 0 {
				return d.Errf("validity days is already specified: %d", iss.ValidityDays)
			}
			days, err := strconv.Atoi(d.Val())
			if err != nil {
				return d.Errf("invalid number of days %s: %v", d.Val(), err)
			}
			iss.ValidityDays = days

		case "alt_http_port":
			if !d.NextArg() {
				return d.ArgErr()
			}
			port, err := strconv.Atoi(d.Val())
			if err != nil {
				return d.Errf("invalid port %s: %v", d.Val(), err)
			}
			iss.AlternateHTTPPort = port

		case "dns":
			if !d.NextArg() {
				return d.ArgErr()
			}
			provName := d.Val()
			if iss.CNAMEValidation == nil {
				iss.CNAMEValidation = new(DNSChallengeConfig)
			}
			unm, err := caddyfile.UnmarshalModule(d, "dns.providers."+provName)
			if err != nil {
				return err
			}
			iss.CNAMEValidation.ProviderRaw = caddyconfig.JSONModuleObject(unm, "name", provName, nil)

		case "propagation_delay":
			if !d.NextArg() {
				return d.ArgErr()
			}
			delayStr := d.Val()
			delay, err := caddy.ParseDuration(delayStr)
			if err != nil {
				return d.Errf("invalid propagation_delay duration %s: %v", delayStr, err)
			}
			if iss.CNAMEValidation == nil {
				iss.CNAMEValidation = new(DNSChallengeConfig)
			}
			iss.CNAMEValidation.PropagationDelay = caddy.Duration(delay)

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
			if iss.CNAMEValidation == nil {
				iss.CNAMEValidation = new(DNSChallengeConfig)
			}
			iss.CNAMEValidation.PropagationTimeout = caddy.Duration(timeout)

		case "resolvers":
			if iss.CNAMEValidation == nil {
				iss.CNAMEValidation = new(DNSChallengeConfig)
			}
			iss.CNAMEValidation.Resolvers = d.RemainingArgs()
			if len(iss.CNAMEValidation.Resolvers) == 0 {
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
			if iss.CNAMEValidation == nil {
				iss.CNAMEValidation = new(DNSChallengeConfig)
			}
			iss.CNAMEValidation.TTL = caddy.Duration(ttl)

		default:
			return d.Errf("unrecognized zerossl issuer property: %s", d.Val())
		}
	}

	return nil
}

// Interface guards
var (
	_ certmagic.Issuer  = (*ZeroSSLIssuer)(nil)
	_ certmagic.Revoker = (*ZeroSSLIssuer)(nil)
	_ caddy.Provisioner = (*ZeroSSLIssuer)(nil)
)
