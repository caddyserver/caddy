package caddygzip

import (
	"compress/flate"
	"compress/gzip" // TODO: consider using https://github.com/klauspost/compress/gzip

	"github.com/caddyserver/caddy2"
	"github.com/caddyserver/caddy2/modules/caddyhttp/encode"
)

func init() {
	caddy2.RegisterModule(caddy2.Module{
		Name: "http.encoders.gzip",
		New:  func() interface{} { return new(Gzip) },
	})
}

// Gzip can create gzip encoders.
type Gzip struct {
	Level int `json:"level,omitempty"`
}

// NewEncoder returns a new gzip writer.
func (g Gzip) NewEncoder() encode.Encoder {
	if g.Level <= flate.NoCompression {
		g.Level = defaultGzipLevel
	}
	if g.Level > flate.BestCompression {
		g.Level = flate.BestCompression
	}
	writer, _ := gzip.NewWriterLevel(nil, g.Level)
	return writer
}

// Informed from http://blog.klauspost.com/gzip-performance-for-go-webservers/
var defaultGzipLevel = 5
