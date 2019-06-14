package caddyzstd

import (
	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/modules/caddyhttp/encode"
	"github.com/klauspost/compress/zstd"
)

func init() {
	caddy.RegisterModule(caddy.Module{
		Name: "http.encoders.zstd",
		New:  func() interface{} { return new(Zstd) },
	})
}

// Zstd can create zstd encoders.
type Zstd struct{}

// NewEncoder returns a new gzip writer.
func (z Zstd) NewEncoder() encode.Encoder {
	writer, _ := zstd.NewWriter(nil)
	return writer
}

// Interface guard
var _ encode.Encoding = (*Zstd)(nil)
