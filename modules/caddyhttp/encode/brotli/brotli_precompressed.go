package caddybrotli

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/encode"
)

func init() {
	caddy.RegisterModule(BrotliPrecompressed{})
}

// BrotliPrecompressed provides the file extension for files precompressed with brotli encoding
type BrotliPrecompressed struct{}

// CaddyModule returns the Caddy module information.
func (BrotliPrecompressed) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.precompressed.br",
		New: func() caddy.Module { return new(BrotliPrecompressed) },
	}
}

// AcceptEncoding returns the name of the encoding as
// used in the Accept-Encoding request headers.
func (BrotliPrecompressed) AcceptEncoding() string { return "br" }

// Suffix returns the filename suffix of precomressed files
func (BrotliPrecompressed) Suffix() string { return ".br" }

// Interface guards
var _ encode.Precompressed = (*BrotliPrecompressed)(nil)
