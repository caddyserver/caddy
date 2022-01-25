package caddytls

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"
	"tailscale.com/client/tailscale"
)

func init() {
	caddy.RegisterModule(Tailscale{})
	caddy.RegisterModule(HTTPCertGetter{})
}

// Tailscale is a module that can get certificates from the local Tailscale process.
type Tailscale struct {
	// Whether to cache returned certificates in Caddy's in-memory certificate cache.
	// If true, Tailscale will only be asked for a certificate if it does not already
	// exist in Caddy's cache, or if it is nearing expiration.
	Cache bool `json:"cache,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (Tailscale) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.get_certificate.tailscale",
		New: func() caddy.Module { return new(Tailscale) },
	}
}

func (ts Tailscale) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, bool, error) {
	cert, err := tailscale.GetCertificate(hello)
	return cert, ts.Cache, err
}

// UnmarshalCaddyfile deserializes Caddyfile tokens into ts.
//
//     ... tailscale {
//         cache
//     }
//
func (ts *Tailscale) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "cache":
				if ts.Cache {
					return d.Errf("caching is already enabled")
				}
				if d.NextArg() {
					return d.ArgErr()
				}
				ts.Cache = true
			default:
				return d.Errf("unrecognized tailscale property: %s", d.Val())
			}
		}
	}
	return nil
}

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
	// To be valid, the response must be HTTP 200 with ... TODO: body format?
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

func (hcg HTTPCertGetter) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, bool, error) {
	sigs := make([]string, len(hello.SignatureSchemes))
	for i, sig := range hello.SignatureSchemes {
		sigs[i] = fmt.Sprintf("%x", uint16(sig))
	}
	suites := make([]string, len(hello.CipherSuites))
	for i, cs := range hello.CipherSuites {
		suites[i] = fmt.Sprintf("%x", cs)
	}

	parsed, err := url.Parse(hcg.URL)
	if err != nil {
		return nil, false, err
	}
	qs := parsed.Query()
	qs.Set("server_name", hello.ServerName)
	qs.Set("signature_schemes", strings.Join(sigs, ","))
	qs.Set("cipher_suites", strings.Join(suites, ","))
	parsed.RawQuery = qs.Encode()

	req, err := http.NewRequestWithContext(hcg.ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, false, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("got HTTP %d", resp.StatusCode)
	}

	return nil, false, fmt.Errorf("TODO: not implemented")
}

// UnmarshalCaddyfile deserializes Caddyfile tokens into ts.
//
//     ... http <url>
//
func (hcg *HTTPCertGetter) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if !d.NextArg() {
			return d.ArgErr()
		}
		hcg.URL = d.Val()
		if d.NextArg() {
			return d.ArgErr()
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			return d.Err("block not allowed here")
		}
	}
	return nil
}

// Interface guards
var (
	_ certmagic.CertificateGetter = (*Tailscale)(nil)
	_ caddyfile.Unmarshaler       = (*Tailscale)(nil)

	_ certmagic.CertificateGetter = (*HTTPCertGetter)(nil)
	_ caddyfile.Unmarshaler       = (*HTTPCertGetter)(nil)
)
