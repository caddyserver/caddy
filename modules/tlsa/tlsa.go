package tlsa

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(TLSAHook{})
	httpcaddyfile.RegisterHandlerDirective("tlsa", parseCaddyfile)
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var handler TLSAHook
	err := handler.UnmarshalCaddyfile(h.Dispenser)
	return &handler, err
}

type TLSAHook struct{}

func (TLSAHook) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.tlsa",
		New: func() caddy.Module { return new(TLSAHook) },
	}
}

func (h *TLSAHook) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if r.TLS != nil {
		caddy.Log().Named("tlsa").Info(fmt.Sprintf("TLS connection state: PeerCertificates count=%d", len(r.TLS.PeerCertificates)))
		if len(r.TLS.PeerCertificates) > 0 {
			h.printTLSA(r.TLS.PeerCertificates[0])
		} else {
			caddy.Log().Named("tlsa").Info("No peer certificates presented")
		}
	} else {
		caddy.Log().Named("tlsa").Info("No TLS connection")
	}
	return next.ServeHTTP(w, r)
}

func (h *TLSAHook) printTLSA(cert *x509.Certificate) {
	if cert == nil {
		return
	}
	pubKeyDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		caddy.Log().Named("tlsa").Error(fmt.Sprintf("failed to marshal public key: %v", err))
		return
	}
	hash := sha256.Sum256(pubKeyDER)
	hashHex := hex.EncodeToString(hash[:])
	fmt.Printf("[TLSA] TLSA Record: _443._tcp.%s. IN TLSA 3 1 1 %s\n", cert.Subject.CommonName, hashHex)
}

func (h *TLSAHook) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.NextBlock(0) {
		return d.Errf("unexpected tokens in 'tlsa' block")
	}
	return nil
}

var (
	_ caddy.Module                 = (*TLSAHook)(nil)
	_ caddyhttp.MiddlewareHandler = (*TLSAHook)(nil)
	_ caddyfile.Unmarshaler        = (*TLSAHook)(nil)
)
