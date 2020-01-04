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

package caddybrotli

import (
	"fmt"
	"strconv"

	"github.com/andybalholm/brotli"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/encode"
)

func init() {
	caddy.RegisterModule(Brotli{})
}

// Brotli can create brotli encoders. Note that brotli
// is not known for great encoding performance, and
// its use during requests is discouraged; instead,
// pre-compress the content instead.
type Brotli struct {
	Quality *int `json:"quality,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (Brotli) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.encoders.brotli",
		New: func() caddy.Module { return new(Brotli) },
	}
}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens.
func (b *Brotli) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if !d.NextArg() {
			continue
		}
		qualityStr := d.Val()
		quality, err := strconv.Atoi(qualityStr)
		if err != nil {
			return err
		}
		b.Quality = &quality
	}
	return nil
}

// Validate validates b's configuration.
func (b Brotli) Validate() error {
	if b.Quality != nil {
		quality := *b.Quality
		if quality < brotli.BestSpeed {
			return fmt.Errorf("quality too low; must be >= %d", brotli.BestSpeed)
		}
		if quality > brotli.BestCompression {
			return fmt.Errorf("quality too high; must be <= %d", brotli.BestCompression)
		}
	}
	return nil
}

// AcceptEncoding returns the name of the encoding as
// used in the Accept-Encoding request headers.
func (Brotli) AcceptEncoding() string { return "br" }

// NewEncoder returns a new brotli writer.
func (b Brotli) NewEncoder() encode.Encoder {
	quality := brotli.DefaultCompression
	if b.Quality != nil {
		quality = *b.Quality
	}
	return brotli.NewWriterLevel(nil, quality)
}

// Interface guards
var (
	_ encode.Encoding       = (*Brotli)(nil)
	_ caddy.Validator       = (*Brotli)(nil)
	_ caddyfile.Unmarshaler = (*Brotli)(nil)
)
