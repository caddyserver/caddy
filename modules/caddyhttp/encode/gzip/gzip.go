package caddygzip

import (
	"compress/flate"
	"compress/gzip" // TODO: consider using https://github.com/klauspost/compress/gzip
	"fmt"

	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/modules/caddyhttp/encode"
)

func init() {
	caddy.RegisterModule(caddy.Module{
		Name: "http.encoders.gzip",
		New:  func() interface{} { return new(Gzip) },
	})
}

// Gzip can create gzip encoders.
type Gzip struct {
	Level int `json:"level,omitempty"`
}

// Provision provisions g's configuration.
func (g *Gzip) Provision(ctx caddy.Context) error {
	if g.Level == 0 {
		g.Level = defaultGzipLevel
	}
	return nil
}

// Validate validates g's configuration.
func (g Gzip) Validate() error {
	if g.Level < flate.NoCompression {
		return fmt.Errorf("quality too low; must be >= %d", flate.NoCompression)
	}
	if g.Level > flate.BestCompression {
		return fmt.Errorf("quality too high; must be <= %d", flate.BestCompression)
	}
	return nil
}

// NewEncoder returns a new gzip writer.
func (g Gzip) NewEncoder() encode.Encoder {
	writer, _ := gzip.NewWriterLevel(nil, g.Level)
	return writer
}

// Informed from http://blog.klauspost.com/gzip-performance-for-go-webservers/
var defaultGzipLevel = 5

// Interface guards
var (
	_ encode.Encoding    = (*Gzip)(nil)
	_ caddy.Provisioner = (*Gzip)(nil)
	_ caddy.Validator   = (*Gzip)(nil)
)
