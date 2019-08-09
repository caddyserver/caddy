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

package headers

import (
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/caddyconfig/httpcaddyfile"
)

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens. Syntax:
//
//     headers [<matcher>] [[+|-]<field> <value>] {
//         [+][<field>] [<value>]
//         [-<field>]
//     }
//
// Either a block can be opened or a single header field can be configured
// in the first line, but not both in the same directive.
func (h *Headers) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		// first see if headers are in the initial line
		var hasArgs bool
		if d.NextArg() {
			hasArgs = true
			field := d.Val()
			d.NextArg()
			value := d.Val()
			h.processCaddyfileLine(field, value)
		}

		// if not, they should be in a block
		for d.NextBlock() {
			if hasArgs {
				return d.Err("cannot specify headers in both arguments and block")
			}
			field := d.Val()
			var value string
			if d.NextArg() {
				value = d.Val()
			}
			h.processCaddyfileLine(field, value)
		}
	}
	return nil
}

func (h *Headers) processCaddyfileLine(field, value string) {
	if strings.HasPrefix(field, "+") {
		if h.Response == nil {
			h.Response = &RespHeaderOps{HeaderOps: new(HeaderOps)}
		}
		if h.Response.Add == nil {
			h.Response.Add = make(http.Header)
		}
		h.Response.Add.Set(field[1:], value)
	} else if strings.HasPrefix(field, "-") {
		if h.Response == nil {
			h.Response = &RespHeaderOps{HeaderOps: new(HeaderOps)}
		}
		h.Response.Delete = append(h.Response.Delete, field[1:])
		h.Response.Deferred = true
	} else {
		if h.Response == nil {
			h.Response = &RespHeaderOps{HeaderOps: new(HeaderOps)}
		}
		if h.Response.Set == nil {
			h.Response.Set = make(http.Header)
		}
		h.Response.Set.Set(field, value)
	}
}

// Bucket returns the HTTP Caddyfile handler bucket number.
func (h Headers) Bucket() int { return 3 }

// Interface guard
var _ httpcaddyfile.HandlerDirective = (*Headers)(nil)
