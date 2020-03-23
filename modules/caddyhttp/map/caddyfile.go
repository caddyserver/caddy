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

package mmap

import (
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("map", parseCaddyfile)
}

// parseCaddyfile sets up the handler for a map from
// Caddyfile tokens. Syntax:
//
//     map source dest {
//         [[default] value]
//         [+][<value|regexp> [<replacement>]]
//     }
//
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	m := new(Handler)

	for h.Next() {
		// first see if source and dest are configured
		if h.NextArg() {
			m.Source = h.Val()
			if h.NextArg() {
				m.Destination = h.Val()
			}
		}

		// load the rules
		for h.NextBlock(0) {
			key := h.Val()
			if key == "default" {
				args := h.RemainingArgs()
				if len(args) != 1 {
					return m, h.ArgErr()
				}
				m.Default = args[0]
			} else {
				args := h.RemainingArgs()
				if len(args) != 1 {
					return m, h.ArgErr()
				}
				m.Items = append(m.Items, Item{Key: key, Value: args[0]})
			}
		}
	}

	return m, nil
}
