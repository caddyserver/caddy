package caddytls

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/caddyserver/certmagic"
	"github.com/tailscale/tscert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func init() {
	caddy.RegisterModule(Tailscale{})
	caddy.RegisterModule(HTTPCertGetter{})
}

// Tailscale is a module that can get certificates from the local Tailscale process.
type Tailscale struct {
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Tailscale) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.get_certificate.tailscale",
		New: func() caddy.Module { return new(Tailscale) },
	}
}

func (ts *Tailscale) Provision(ctx caddy.Context) error {
	ts.logger = ctx.Logger()
	return nil
}

func (ts Tailscale) GetCertificate(ctx context.Context, hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	canGetCert, err := ts.canHazCertificate(ctx, hello)
	if err == nil && !canGetCert {
		return nil, nil // pass-thru: Tailscale can't offer a cert for this name
	}
	if err != nil {
		if c := ts.logger.Check(zapcore.WarnLevel, "could not get status; will try to get certificate anyway"); c != nil {
			c.Write(zap.Error(err))
		}
	}
	return tscert.GetCertificateWithContext(ctx, hello)
}

// canHazCertificate returns true if Tailscale reports it can get a certificate for the given ClientHello.
func (ts Tailscale) canHazCertificate(ctx context.Context, hello *tls.ClientHelloInfo) (bool, error) {
	if !strings.HasSuffix(strings.ToLower(hello.ServerName), tailscaleDomainAliasEnding) {
		return false, nil
	}
	status, err := tscert.GetStatus(ctx)
	if err != nil {
		return false, err
	}
	for _, domain := range status.CertDomains {
		if certmagic.MatchWildcard(hello.ServerName, domain) {
			return true, nil
		}
	}
	return false, nil
}

// UnmarshalCaddyfile deserializes Caddyfile tokens into ts.
//
//	... tailscale
func (Tailscale) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume cert manager name
	if d.NextArg() {
		return d.ArgErr()
	}
	return nil
}

// tailscaleDomainAliasEnding is the ending for all Tailscale custom domains.
const tailscaleDomainAliasEnding = ".ts.net"

// HTTPCertGetter can get a certificate via HTTP(S) request.
type HTTPCertGetter struct {
	// The URL from which to download the certificate. Required.
	//
	// The URL will be augmented with query string parameters taken
	// from the TLS handshake:
	//
	// - server_name: The SNI value
	// - signature_schemes: Comma-separated list of hex IDs of signatures
	// - cipher_suites: Comma-separated list of hex IDs of cipher suites
	//
	// To be valid, the response must be HTTP 200 with a PEM body
	// consisting of blocks for the certificate chain and the private
	// key.
	//
	// To indicate that this manager is not managing a certificate for
	// the described handshake, the endpoint should return HTTP 204
	// (No Content). Error statuses will indicate that the manager is
	// capable of providing a certificate but was unable to.
	URL string `json:"url,omitempty"`

	ctx context.Context
}

// CaddyModule returns the Caddy module information.
func (hcg HTTPCertGetter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.get_certificate.http",
		New: func() caddy.Module { return new(HTTPCertGetter) },
	}
}

func (hcg *HTTPCertGetter) Provision(ctx caddy.Context) error {
	hcg.ctx = ctx
	if hcg.URL == "" {
		return fmt.Errorf("URL is required")
	}
	return nil
}

func (hcg HTTPCertGetter) GetCertificate(ctx context.Context, hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	sigs := make([]string, len(hello.SignatureSchemes))
	for i, sig := range hello.SignatureSchemes {
		sigs[i] = fmt.Sprintf("%x", uint16(sig)) // you won't believe what %x uses if the val is a Stringer
	}
	suites := make([]string, len(hello.CipherSuites))
	for i, cs := range hello.CipherSuites {
		suites[i] = fmt.Sprintf("%x", cs)
	}

	parsed, err := url.Parse(hcg.URL)
	if err != nil {
		return nil, err
	}
	qs := parsed.Query()
	qs.Set("server_name", hello.ServerName)
	qs.Set("signature_schemes", strings.Join(sigs, ","))
	qs.Set("cipher_suites", strings.Join(suites, ","))
	parsed.RawQuery = qs.Encode()

	req, err := http.NewRequestWithContext(hcg.ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		// endpoint is not managing certs for this handshake
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("got HTTP %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	cert, err := tlsCertFromCertAndKeyPEMBundle(bodyBytes)
	if err != nil {
		return nil, err
	}

	return &cert, nil
}

// UnmarshalCaddyfile deserializes Caddyfile tokens into ts.
//
//	... http <url>
func (hcg *HTTPCertGetter) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume cert manager name

	if !d.NextArg() {
		return d.ArgErr()
	}
	hcg.URL = d.Val()

	if d.NextArg() {
		return d.ArgErr()
	}
	if d.NextBlock(0) {
		return d.Err("block not allowed here")
	}
	return nil
}

// Interface guards
var (
	_ certmagic.Manager     = (*Tailscale)(nil)
	_ caddy.Provisioner     = (*Tailscale)(nil)
	_ caddyfile.Unmarshaler = (*Tailscale)(nil)

	_ certmagic.Manager     = (*HTTPCertGetter)(nil)
	_ caddy.Provisioner     = (*HTTPCertGetter)(nil)
	_ caddyfile.Unmarshaler = (*HTTPCertGetter)(nil)
)
