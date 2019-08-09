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

package templates

import (
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
)

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens. Syntax:
//
//     templates [<matcher>] {
//         mime <types...>
//         between <open_delim> <close_delim>
//         root <path>
//     }
//
func (t *Templates) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock() {
			switch d.Val() {
			case "mime":
				t.MIMETypes = d.RemainingArgs()
				if len(t.MIMETypes) == 0 {
					return d.ArgErr()
				}
			case "between":
				t.Delimiters = d.RemainingArgs()
				if len(t.Delimiters) != 2 {
					return d.ArgErr()
				}
			case "root":
				if !d.Args(&t.IncludeRoot) {
					return d.ArgErr()
				}
			}
		}
	}

	if t.IncludeRoot == "" {
		t.IncludeRoot = "{http.var.root}"
	}

	return nil
}

// Bucket returns the HTTP Caddyfile handler bucket number.
func (t Templates) Bucket() int { return 5 }

// Interface guard
var _ httpcaddyfile.HandlerDirective = (*Templates)(nil)
