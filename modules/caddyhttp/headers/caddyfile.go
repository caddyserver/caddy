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

	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("headers", parseCaddyfile)
}

// parseCaddyfile sets up the handler from Caddyfile tokens. Syntax:
//
//     headers [<matcher>] [[+|-]<field> <value>] {
//         [+][<field>] [<value>]
//         [-<field>]
//     }
//
// Either a block can be opened or a single header field can be configured
// in the first line, but not both in the same directive.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	hdr := new(Headers)
	for h.Next() {
		// first see if headers are in the initial line
		var hasArgs bool
		if h.NextArg() {
			hasArgs = true
			field := h.Val()
			h.NextArg()
			value := h.Val()
			processCaddyfileLine(hdr, field, value)
		}

		// if not, they should be in a block
		for h.NextBlock(0) {
			if hasArgs {
				return nil, h.Err("cannot specify headers in both arguments and block")
			}
			field := h.Val()
			var value string
			if h.NextArg() {
				value = h.Val()
			}
			processCaddyfileLine(hdr, field, value)
		}
	}
	return hdr, nil
}

func processCaddyfileLine(hdr *Headers, field, value string) {
	if strings.HasPrefix(field, "+") {
		if hdr.Response == nil {
			hdr.Response = &RespHeaderOps{HeaderOps: new(HeaderOps)}
		}
		if hdr.Response.Add == nil {
			hdr.Response.Add = make(http.Header)
		}
		hdr.Response.Add.Set(field[1:], value)
	} else if strings.HasPrefix(field, "-") {
		if hdr.Response == nil {
			hdr.Response = &RespHeaderOps{HeaderOps: new(HeaderOps)}
		}
		hdr.Response.Delete = append(hdr.Response.Delete, field[1:])
		hdr.Response.Deferred = true
	} else {
		if hdr.Response == nil {
			hdr.Response = &RespHeaderOps{HeaderOps: new(HeaderOps)}
		}
		if hdr.Response.Set == nil {
			hdr.Response.Set = make(http.Header)
		}
		hdr.Response.Set.Set(field, value)
	}
}
