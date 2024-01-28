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
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/acme"
	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func init() {
	caddy.RegisterModule(new(ZeroSSLIssuer))
}

// ZeroSSLIssuer makes an ACME issuer for getting certificates
// from ZeroSSL by automatically generating EAB credentials.
// Please be sure to set a valid email address in your config
// so you can access/manage your domains in your ZeroSSL account.
//
// This issuer is only needed for automatic generation of EAB
// credentials. If manually configuring/reusing EAB credentials,
// the standard ACMEIssuer may be used if desired.
type ZeroSSLIssuer struct {
	*ACMEIssuer

	// The API key (or "access key") for using the ZeroSSL API.
	// This is optional, but can be used if you have an API key
	// already and don't want to supply your email address.
	APIKey string `json:"api_key,omitempty"`

	// Gives the user the option to use the ZeroSSL API
	// to issue certificates.
	UseZeroSSlApi bool `json:"use_zerossl_api,omitempty"`

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
	iss.logger = ctx.Logger()
	if iss.ACMEIssuer == nil {
		iss.ACMEIssuer = new(ACMEIssuer)
	}
	if iss.ACMEIssuer.CA == "" {
		iss.ACMEIssuer.CA = certmagic.ZeroSSLProductionCA
	}
	return iss.ACMEIssuer.Provision(ctx)
}

// newAccountCallback generates EAB if not already provided. It also sets a valid default contact on the account if not set.
func (iss *ZeroSSLIssuer) newAccountCallback(ctx context.Context, acmeIss *certmagic.ACMEIssuer, acct acme.Account) (acme.Account, error) {
	if acmeIss.ExternalAccount != nil {
		return acct, nil
	}
	var err error
	acmeIss.ExternalAccount, acct, err = iss.generateEABCredentials(ctx, acct)
	return acct, err
}

// generateEABCredentials generates EAB credentials using the API key if provided,
// otherwise using the primary contact email on the issuer. If an email is not set
// on the issuer, a default generic email is used.
func (iss *ZeroSSLIssuer) generateEABCredentials(ctx context.Context, acct acme.Account) (*acme.EAB, acme.Account, error) {
	var endpoint string
	var body io.Reader

	// there are two ways to generate EAB credentials: authenticated with
	// their API key, or unauthenticated with their email address
	if iss.APIKey != "" {
		apiKey := caddy.NewReplacer().ReplaceAll(iss.APIKey, "")
		if apiKey == "" {
			return nil, acct, fmt.Errorf("missing API key: '%v'", iss.APIKey)
		}
		qs := url.Values{"access_key": []string{apiKey}}
		endpoint = fmt.Sprintf("%s/eab-credentials?%s", zerosslAPIBase, qs.Encode())
	} else {
		email := iss.Email
		if email == "" {
			iss.logger.Warn("missing email address for ZeroSSL; it is strongly recommended to set one for next time")
			email = "caddy@zerossl.com" // special email address that preserves backwards-compat, but which black-holes dashboard features, oh well
		}
		if len(acct.Contact) == 0 {
			// we borrow the email from config or the default email, so ensure it's saved with the account
			acct.Contact = []string{"mailto:" + email}
		}
		endpoint = zerosslAPIBase + "/eab-credentials-email"
		form := url.Values{"email": []string{email}}
		body = strings.NewReader(form.Encode())
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return nil, acct, fmt.Errorf("forming request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("User-Agent", certmagic.UserAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, acct, fmt.Errorf("performing EAB credentials request: %v", err)
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
		return nil, acct, fmt.Errorf("decoding API response: %v", err)
	}
	if result.Error.Code != 0 {
		return nil, acct, fmt.Errorf("failed getting EAB credentials: HTTP %d: %s (code %d)",
			resp.StatusCode, result.Error.Type, result.Error.Code)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, acct, fmt.Errorf("failed getting EAB credentials: HTTP %d", resp.StatusCode)
	}

	iss.logger.Info("generated EAB credentials", zap.String("key_id", result.EABKID))

	return &acme.EAB{
		KeyID:  result.EABKID,
		MACKey: result.EABHMACKey,
	}, acct, nil
}

// initialize modifies the template for the underlying ACMEIssuer
// values by setting the CA endpoint to the ZeroSSL directory and
// setting the NewAccountFunc callback to one which allows us to
// generate EAB credentials only if a new account is being made.
// Since it modifies the stored template, its effect should only
// be needed once, but it is fine to call it repeatedly.
func (iss *ZeroSSLIssuer) initialize() {
	iss.mu.Lock()
	defer iss.mu.Unlock()
	if iss.ACMEIssuer.issuer.NewAccountFunc == nil {
		iss.ACMEIssuer.issuer.NewAccountFunc = iss.newAccountCallback
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
	if !iss.UseZeroSSlApi {
		return iss.ACMEIssuer.Issue(ctx, csr)
	}
	zerosslCertId, err := iss.createCertificate(ctx, csr)
	if err != nil {
		return nil, err
	}
	return iss.dowloadCertificate(ctx, zerosslCertId)
}

// createCertificate calls the create endpoint of the zerossl API and returns the id of the generated certificate
// or an error if the certificate create fails.
func (iss *ZeroSSLIssuer) createCertificate(ctx context.Context, csr *x509.CertificateRequest) (string, error) {
	if iss.APIKey == "" {
		return "", fmt.Errorf("Can't issue a zerossl certificate without an API key")
	}
	qs := url.Values{"access_key": []string{iss.APIKey}}
	endpoint := fmt.Sprintf("%s?%s", zerosslAPICerts, qs.Encode())
	form := url.Values{"certificate_domains": []string{strings.Join(namesFromCSR(csr), ",")}, "certificate_csr": []string{string(csr.Raw)}}
	body := strings.NewReader(form.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return "", fmt.Errorf("ZeroSSL create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("performing create certificate request: %v", err)
	}
	defer resp.Body.Close()
	var result struct {
		Id string `json:"id"`
	}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return "", fmt.Errorf("decoding zerossl create API response: %v", err)
	}
	return result.Id, nil
}

// downloadCertificate calls the download (inline) ednpoint of the zerossl API with the given certId and
// return the corresponding certificate.
func (iss *ZeroSSLIssuer) dowloadCertificate(ctx context.Context, certId string) (*certmagic.IssuedCertificate, error) {
	if iss.APIKey == "" {
		return nil, fmt.Errorf("Can't download a zerossl certificate without an API key")
	}
	qs := url.Values{"access_key": []string{iss.APIKey}}
	endpoint := fmt.Sprintf("%s/%s/download/return?%s", zerosslAPICerts, certId, qs.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("ZeroSSL dowload request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("performing dowload certificate request: %v", err)
	}
	defer resp.Body.Close()
	var result struct {
		CertificateCrt    string `json:"certificate.crt"`
		CertificateBundle string `json:"ca_bundle.crt"`
	}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, fmt.Errorf("decoding zerossl download API response: %v", err)
	}
	return &certmagic.IssuedCertificate{Certificate: []byte(result.CertificateCrt)}, nil
}

func namesFromCSR(csr *x509.CertificateRequest) []string {
	nameSet := []string{}
	nameSet = append(nameSet, csr.Subject.CommonName)
	nameSet = append(nameSet, csr.DNSNames...)
	nameSet = append(nameSet, csr.EmailAddresses...)
	for _, v := range csr.IPAddresses {
		nameSet = append(nameSet, v.String())
	}
	for _, v := range csr.URIs {
		nameSet = append(nameSet, v.String())
	}

	return nameSet
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
//	... zerossl [<api_key>] [use_ssl_api]{
//	    ...
//	}
//
// Any of the subdirectives for the ACME issuer can be used in the block.
func (iss *ZeroSSLIssuer) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume issuer name
	if d.NextArg() {
		iss.APIKey = d.Val()
		if d.NextArg() {
			if d.Val() != "use_ssl_api" {
				return d.ArgErr()
			}
			iss.UseZeroSSlApi = true
		}
		if d.NextArg() {
			return d.ArgErr()
		}
	}

	if iss.ACMEIssuer == nil {
		iss.ACMEIssuer = new(ACMEIssuer)
	}
	err := iss.ACMEIssuer.UnmarshalCaddyfile(d.NewFromNextSegment())
	if err != nil {
		return err
	}
	return nil
}

const (
	zerosslAPIBase  = "https://api.zerossl.com/acme"
	zerosslAPICerts = "https://api.zerossl.com/certificates"
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
