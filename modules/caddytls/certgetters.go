package caddytls

import (
	"crypto/tls"

	"github.com/caddyserver/caddy/v2"
	"tailscale.com/client/tailscale"
)

func init() {
	caddy.RegisterModule(Tailscale{})
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
