package testmocks

import (
	"crypto/x509"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

func init() {
	caddy.RegisterModule(new(dummyVerifier))
}

type dummyVerifier struct{}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (dummyVerifier) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	return nil
}

// CaddyModule implements caddy.Module.
func (dummyVerifier) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "tls.client_auth.verifier.dummy",
		New: func() caddy.Module {
			return new(dummyVerifier)
		},
	}
}

// VerifyClientCertificate implements ClientCertificateVerifier.
func (dummyVerifier) VerifyClientCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return nil
}

var (
	_ caddy.Module                       = dummyVerifier{}
	_ caddytls.ClientCertificateVerifier = dummyVerifier{}
	_ caddyfile.Unmarshaler              = dummyVerifier{}
)
