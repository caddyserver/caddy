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
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/acme"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(new(ZeroSSLIssuer))
}

// ZeroSSLIssuer makes an ACME manager
// for managing certificates using ACME.
type ZeroSSLIssuer struct {
	*ACMEIssuer

	// The API key (or "access key") for using the ZeroSSL API.
	APIKey string `json:"api_key,omitempty"`

	mu     sync.Mutex
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (*ZeroSSLIssuer) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.issuance.zerossl",
		New: func() caddy.Module { return new(ZeroSSLIssuer) },
	}
}

// Provision sets up iss.
func (iss *ZeroSSLIssuer) Provision(ctx caddy.Context) error {
	iss.logger = ctx.Logger(iss)

	if iss.ACMEIssuer == nil {
		iss.ACMEIssuer = new(ACMEIssuer)
	}
	err := iss.ACMEIssuer.Provision(ctx)
	if err != nil {
		return err
	}

	return nil
}

func (iss *ZeroSSLIssuer) newAccountCallback(ctx context.Context, am *certmagic.ACMEManager, _ acme.Account) error {
	if am.ExternalAccount != nil {
		return nil
	}
	var err error
	am.ExternalAccount, err = iss.generateEABCredentials(ctx)
	return err
}

func (iss *ZeroSSLIssuer) generateEABCredentials(ctx context.Context) (*acme.EAB, error) {
	var qs url.Values
	var endpoint string

	// there are two ways to generate EAB credentials: authenticated with
	// their API key, or unauthenticated with their email address
	switch {
	case iss.APIKey != "":
		apiKey := caddy.NewReplacer().ReplaceAll(iss.APIKey, "")
		if apiKey == "" {
			return nil, fmt.Errorf("missing API key: '%v'", iss.APIKey)
		}
		qs = url.Values{"access_key": []string{apiKey}}
		endpoint = fmt.Sprintf("%s/eab-credentials?%s", zerosslAPIBase, qs.Encode())

	case iss.Email != "":
		email := caddy.NewReplacer().ReplaceAll(iss.Email, "")
		if email == "" {
			return nil, fmt.Errorf("missing email: '%v'", iss.Email)
		}
		qs = url.Values{"email": []string{email}}
		endpoint = fmt.Sprintf("%s/eab-credentials-email?%s", zerosslAPIBase, qs.Encode())

	default:
		return nil, fmt.Errorf("must configure either an API key or email address to use ZeroSSL without explicit EAB")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("forming request: %v", err)
	}
	req.Header.Set("User-Agent", certmagic.UserAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("performing EAB credentials request: %v", err)
	}
	defer resp.Body.Close()

	var result struct {
		Success bool `json:"success"`
		Error   struct {
			Code int    `json:"code"`
			Type string `json:"type"`
		} `json:"error"`
		EABKID     string `json:"eab_kid"`
		EABHMACKey string `json:"eab_hmac_key"`
	}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, fmt.Errorf("decoding API response: %v", err)
	}
	if result.Error.Code != 0 {
		return nil, fmt.Errorf("failed getting EAB credentials: HTTP %d: %s (code %d)",
			resp.StatusCode, result.Error.Type, result.Error.Code)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed getting EAB credentials: HTTP %d", resp.StatusCode)
	}

	iss.logger.Info("generated EAB credentials", zap.String("key_id", result.EABKID))

	return &acme.EAB{
		KeyID:  result.EABKID,
		MACKey: result.EABHMACKey,
	}, nil
}

// initialize modifies the template for the underlying ACMEManager
// values by setting the CA endpoint to the ZeroSSL directory and
// setting the NewAccountFunc callback to one which allows us to
// generate EAB credentials only if a new account is being made.
// Since it modifies the stored template, its effect should only
// be needed once, but it is fine to call it repeatedly.
func (iss *ZeroSSLIssuer) initialize() {
	iss.mu.Lock()
	defer iss.mu.Unlock()
	if iss.template.CA == "" {
		iss.template.CA = zerosslACMEDirectory
	}
	if iss.template.NewAccountFunc == nil {
		iss.template.NewAccountFunc = iss.newAccountCallback
	}
}

// PreCheck implements the certmagic.PreChecker interface.
func (iss *ZeroSSLIssuer) PreCheck(ctx context.Context, names []string, interactive bool) error {
	iss.initialize()
	return iss.ACMEIssuer.PreCheck(ctx, names, interactive)
}

// Issue obtains a certificate for the given csr.
func (iss *ZeroSSLIssuer) Issue(ctx context.Context, csr *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	iss.initialize()
	return iss.ACMEIssuer.Issue(ctx, csr)
}

// IssuerKey returns the unique issuer key for the configured CA endpoint.
func (iss *ZeroSSLIssuer) IssuerKey() string {
	iss.initialize()
	return iss.ACMEIssuer.IssuerKey()
}

// Revoke revokes the given certificate.
func (iss *ZeroSSLIssuer) Revoke(ctx context.Context, cert certmagic.CertificateResource, reason int) error {
	iss.initialize()
	return iss.ACMEIssuer.Revoke(ctx, cert, reason)
}

// UnmarshalCaddyfile deserializes Caddyfile tokens into iss.
//
//     ... zerossl <api_key> {
//         ...
//     }
//
// Any of the subdirectives for the ACME issuer can be used in the block.
func (iss *ZeroSSLIssuer) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if !d.AllArgs(&iss.APIKey) {
			return d.ArgErr()
		}

		if iss.ACMEIssuer == nil {
			iss.ACMEIssuer = new(ACMEIssuer)
		}
		err := iss.ACMEIssuer.UnmarshalCaddyfile(d.NewFromNextSegment())
		if err != nil {
			return err
		}
	}
	return nil
}

const (
	zerosslACMEDirectory = "https://acme.zerossl.com/v2/DV90"
	zerosslAPIBase       = "https://api.zerossl.com/acme"
)

// Interface guards
var (
	_ certmagic.PreChecker = (*ZeroSSLIssuer)(nil)
	_ certmagic.Issuer     = (*ZeroSSLIssuer)(nil)
	_ certmagic.Revoker    = (*ZeroSSLIssuer)(nil)
	_ caddy.Provisioner    = (*ZeroSSLIssuer)(nil)
	_ ConfigSetter         = (*ZeroSSLIssuer)(nil)

	// a type which properly embeds an ACMEIssuer should implement
	// this interface so it can be treated as an ACMEIssuer
	_ interface{ GetACMEIssuer() *ACMEIssuer } = (*ZeroSSLIssuer)(nil)
)
