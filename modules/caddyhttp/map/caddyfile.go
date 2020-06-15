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
//     The map takes a <source> variable and maps it into the <dest> variable. The mapping process
//     will check the <source> variable for the first succesful match against a list of regular expressions.
//     If a succesful match is found the <dest> variable will contain the <replacement> value.
//     If no successful match is found and the <default> is specified then the <dest> will contain the <default> value.
//
//     map <source> <dest> {
//         [default <default>] - used if not match is found
//         [<regexp> <replacement>] - regular expression to match against the sourceo find and the matching replacement
//         ...
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
			expression := h.Val()
			if expression == "default" {
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
				m.Items = append(m.Items, Item{Expression: expression, Value: args[0]})
			}
		}
	}

	return m, nil
}
