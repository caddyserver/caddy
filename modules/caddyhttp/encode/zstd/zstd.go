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
	// Compression level from 1 to 4 (refer to type constants value from zstd.SpeedFastest to zstd.SpeedBestCompression).
	Level zstd.EncoderLevel `json:"level,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (Zstd) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.encoders.zstd",
		New: func() caddy.Module { return new(Zstd) },
	}
}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens.
func (g *Zstd) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume option name
	if !d.NextArg() {
		return nil
	}
	levelStr := d.Val()
	level, err := strconv.Atoi(levelStr)
	if err != nil {
		return err
	}
	g.Level = zstd.EncoderLevel(level)
	return nil
}

// Provision provisions g's configuration.
func (g *Zstd) Provision(ctx caddy.Context) error {
	if g.Level == 0 {
		g.Level = zstd.SpeedDefault
	}
	return nil
}

// Validate validates g's configuration.
func (g Zstd) Validate() error {
	if g.Level < zstd.SpeedFastest {
		return fmt.Errorf("quality too low; must be >= %d", zstd.SpeedFastest)
	}
	if g.Level > zstd.SpeedBestCompression {
		return fmt.Errorf("quality too high; must be <= %d", zstd.SpeedBestCompression)
	}
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
	writer, _ := zstd.NewWriter(
		nil,
		zstd.WithWindowSize(128<<10),
		zstd.WithEncoderConcurrency(1),
		zstd.WithZeroFrames(true),
		zstd.WithEncoderLevel(z.Level),
	)
	return writer
}

// Interface guards
var (
	_ encode.Encoding       = (*Zstd)(nil)
	_ caddyfile.Unmarshaler = (*Zstd)(nil)
)
