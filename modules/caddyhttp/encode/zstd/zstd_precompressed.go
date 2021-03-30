package caddyzstd

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/encode"
)

func init() {
	caddy.RegisterModule(ZstdPrecompressed{})
}

// ZstdPrecompressed provides the file extension for files precompressed with zstandard encoding.
type ZstdPrecompressed struct {
	Zstd
}

// CaddyModule returns the Caddy module information.
func (ZstdPrecompressed) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.precompressed.zstd",
		New: func() caddy.Module { return new(ZstdPrecompressed) },
	}
}

// Suffix returns the filename suffix of precompressed files.
func (ZstdPrecompressed) Suffix() string { return ".zst" }

var _ encode.Precompressed = (*ZstdPrecompressed)(nil)
