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
	httpcaddyfile.RegisterHandlerDirective("header", parseCaddyfile)
	httpcaddyfile.RegisterHandlerDirective("request_header", parseReqHdrCaddyfile)
}

// parseCaddyfile sets up the handler for response headers from
// Caddyfile tokens. Syntax:
//
//     header [<matcher>] [[+|-]<field> [<value|regexp>] [<replacement>]] {
//         [+]<field> [<value|regexp> [<replacement>]]
//         -<field>
//         [defer]
//     }
//
// Either a block can be opened or a single header field can be configured
// in the first line, but not both in the same directive. Header operations
// are deferred to write-time if any headers are being deleted or if the
// 'defer' subdirective is used.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	hdr := new(Handler)

	makeResponseOps := func() {
		if hdr.Response == nil {
			hdr.Response = &RespHeaderOps{
				HeaderOps: new(HeaderOps),
			}
		}
	}

	for h.Next() {
		// first see if headers are in the initial line
		var hasArgs bool
		if h.NextArg() {
			hasArgs = true
			field := h.Val()
			var value, replacement string
			if h.NextArg() {
				value = h.Val()
			}
			if h.NextArg() {
				replacement = h.Val()
			}
			makeResponseOps()
			CaddyfileHeaderOp(hdr.Response.HeaderOps, field, value, replacement)
			if len(hdr.Response.HeaderOps.Delete) > 0 {
				hdr.Response.Deferred = true
			}
		}

		// if not, they should be in a block
		for h.NextBlock(0) {
			field := h.Val()
			if field == "defer" {
				hdr.Response.Deferred = true
				continue
			}
			if hasArgs {
				return nil, h.Err("cannot specify headers in both arguments and block")
			}
			var value, replacement string
			if h.NextArg() {
				value = h.Val()
			}
			if h.NextArg() {
				replacement = h.Val()
			}
			makeResponseOps()
			CaddyfileHeaderOp(hdr.Response.HeaderOps, field, value, replacement)
			if len(hdr.Response.HeaderOps.Delete) > 0 {
				hdr.Response.Deferred = true
			}
		}
	}

	return hdr, nil
}

// parseReqHdrCaddyfile sets up the handler for request headers
// from Caddyfile tokens. Syntax:
//
//     request_header [<matcher>] [[+|-]<field> [<value|regexp>] [<replacement>]]
//
func parseReqHdrCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	hdr := new(Handler)
	for h.Next() {
		if !h.NextArg() {
			return nil, h.ArgErr()
		}
		field := h.Val()

		// sometimes it is habitual for users to suffix a field name with a colon,
		// as if they were writing a curl command or something; see
		// https://caddy.community/t/v2-reverse-proxy-please-add-cors-example-to-the-docs/7349
		field = strings.TrimSuffix(field, ":")

		var value, replacement string
		if h.NextArg() {
			value = h.Val()
		}
		if h.NextArg() {
			replacement = h.Val()
			if h.NextArg() {
				return nil, h.ArgErr()
			}
		}

		if hdr.Request == nil {
			hdr.Request = new(HeaderOps)
		}
		CaddyfileHeaderOp(hdr.Request, field, value, replacement)

		if h.NextArg() {
			return nil, h.ArgErr()
		}
	}
	return hdr, nil
}

// CaddyfileHeaderOp applies a new header operation according to
// field, value, and replacement. The field can be prefixed with
// "+" or "-" to specify adding or removing; otherwise, the value
// will be set (overriding any previous value). If replacement is
// non-empty, value will be treated as a regular expression which
// will be used to search and then replacement will be used to
// complete the substring replacement; in that case, any + or -
// prefix to field will be ignored.
func CaddyfileHeaderOp(ops *HeaderOps, field, value, replacement string) {
	if strings.HasPrefix(field, "+") {
		if ops.Add == nil {
			ops.Add = make(http.Header)
		}
		ops.Add.Set(field[1:], value)
	} else if strings.HasPrefix(field, "-") {
		ops.Delete = append(ops.Delete, field[1:])
	} else {
		if replacement == "" {
			if ops.Set == nil {
				ops.Set = make(http.Header)
			}
			ops.Set.Set(field, value)
		} else {
			if ops.Replace == nil {
				ops.Replace = make(map[string][]Replacement)
			}
			field = strings.TrimLeft(field, "+-")
			ops.Replace[field] = append(
				ops.Replace[field],
				Replacement{
					SearchRegexp: value,
					Replace:      replacement,
				},
			)
		}
	}
}
