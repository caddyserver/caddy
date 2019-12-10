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

package encode

import (
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("encode", parseCaddyfile)
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	enc := new(Encode)
	err := enc.UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		return nil, err
	}
	return enc, nil
}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens. Syntax:
//
//     encode [<matcher>] <formats...> {
//         gzip [<level>]
//         zstd
//         brotli [<quality>]
//     }
//
// Specifying the formats on the first line will use those formats' defaults.
func (enc *Encode) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for _, arg := range d.RemainingArgs() {
			mod, err := caddy.GetModule("http.encoders." + arg)
			if err != nil {
				return fmt.Errorf("finding encoder module '%s': %v", mod, err)
			}
			encoding, ok := mod.New().(Encoding)
			if !ok {
				return fmt.Errorf("module %s is not an HTTP encoding", mod)
			}
			if enc.EncodingsRaw == nil {
				enc.EncodingsRaw = make(caddy.ModuleMap)
			}
			enc.EncodingsRaw[arg] = caddyconfig.JSON(encoding, nil)
		}

		for d.NextBlock(0) {
			name := d.Val()
			mod, err := caddy.GetModule("http.encoders." + name)
			if err != nil {
				return fmt.Errorf("getting encoder module '%s': %v", name, err)
			}
			unm, ok := mod.New().(caddyfile.Unmarshaler)
			if !ok {
				return fmt.Errorf("encoder module '%s' is not a Caddyfile unmarshaler", mod)
			}
			err = unm.UnmarshalCaddyfile(d.NewFromNextTokens())
			if err != nil {
				return err
			}
			encoding, ok := unm.(Encoding)
			if !ok {
				return fmt.Errorf("module %s is not an HTTP encoding", mod)
			}
			if enc.EncodingsRaw == nil {
				enc.EncodingsRaw = make(caddy.ModuleMap)
			}
			enc.EncodingsRaw[name] = caddyconfig.JSON(encoding, nil)
		}
	}

	return nil
}

// Interface guard
var _ caddyfile.Unmarshaler = (*Encode)(nil)
