// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddyzstd

import (
	"fmt"
	"strconv"

	"github.com/klauspost/compress/zstd"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/encode"
)

func init() {
	caddy.RegisterModule(Zstd{})
}

// Zstd can create Zstandard encoders.
type Zstd struct {
	// The compression level. Accepted values: fastest, better, best, default.
	Level string `json:"level,omitempty"`

	// Whether to include the optional 4-byte zstd frame checksum trailer.
	// If unset, the upstream zstd library default is preserved.
	Checksum *bool `json:"checksum,omitempty"`

	// Compression level refer to type constants value from zstd.SpeedFastest to zstd.SpeedBestCompression
	level zstd.EncoderLevel
}

// CaddyModule returns the Caddy module information.
func (Zstd) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.encoders.zstd",
		New: func() caddy.Module { return new(Zstd) },
	}
}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens.
func (z *Zstd) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume option name
	args := d.RemainingArgs()
	switch len(args) {
	case 0:
	case 1:
		if _, err := parseEncoderLevel(args[0]); err != nil {
			return d.Err(err.Error())
		}
		z.Level = args[0]
	default:
		return d.ArgErr()
	}

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "level":
			args := d.RemainingArgs()
			if len(args) != 1 {
				return d.ArgErr()
			}
			if z.Level != "" {
				return d.Err("compression level already specified")
			}
			if _, err := parseEncoderLevel(args[0]); err != nil {
				return d.Err(err.Error())
			}
			z.Level = args[0]

		case "checksum":
			args := d.RemainingArgs()
			if len(args) > 1 {
				return d.ArgErr()
			}
			if z.Checksum != nil {
				return d.Err("checksum already specified")
			}
			enabled := true
			if len(args) == 1 {
				parsed, err := strconv.ParseBool(args[0])
				if err != nil {
					return d.Errf("parsing checksum: invalid boolean value %q", args[0])
				}
				enabled = parsed
			}
			z.Checksum = &enabled

		default:
			return d.Errf("unknown subdirective '%s'", d.Val())
		}
	}

	return nil
}

// Provision provisions z's configuration.
func (z *Zstd) Provision(ctx caddy.Context) error {
	if z.Level == "" {
		z.Level = zstd.SpeedDefault.String()
	}
	level, err := parseEncoderLevel(z.Level)
	if err != nil {
		return err
	}
	z.level = level
	return nil
}

// AcceptEncoding returns the name of the encoding as
// used in the Accept-Encoding request headers.
func (Zstd) AcceptEncoding() string { return "zstd" }

// NewEncoder returns a new Zstandard writer.
func (z Zstd) NewEncoder() encode.Encoder {
	// The default of 8MB for the window is
	// too large for many clients, so we limit
	// it to 128K to lighten their load.
	writer, _ := zstd.NewWriter(nil, z.writerOptions(128<<10)...)
	return writer
}

func (z Zstd) writerOptions(windowSize int) []zstd.EOption {
	opts := []zstd.EOption{
		zstd.WithWindowSize(windowSize),
		zstd.WithEncoderConcurrency(1),
		zstd.WithZeroFrames(true),
		zstd.WithEncoderLevel(z.encoderLevel()),
	}
	if z.Checksum != nil {
		opts = append(opts, zstd.WithEncoderCRC(*z.Checksum))
	}
	return opts
}

func (z Zstd) encoderLevel() zstd.EncoderLevel {
	if z.level != 0 {
		return z.level
	}
	if z.Level != "" {
		if level, err := parseEncoderLevel(z.Level); err == nil {
			return level
		}
	}
	return zstd.SpeedDefault
}

func parseEncoderLevel(level string) (zstd.EncoderLevel, error) {
	if ok, encLevel := zstd.EncoderLevelFromString(level); ok {
		return encLevel, nil
	}
	return 0, fmt.Errorf("unexpected compression level, use one of '%s', '%s', '%s', '%s'",
		zstd.SpeedFastest,
		zstd.SpeedBetterCompression,
		zstd.SpeedBestCompression,
		zstd.SpeedDefault,
	)
}

// Interface guards
var (
	_ encode.Encoding       = (*Zstd)(nil)
	_ caddyfile.Unmarshaler = (*Zstd)(nil)
	_ caddy.Provisioner     = (*Zstd)(nil)
)
