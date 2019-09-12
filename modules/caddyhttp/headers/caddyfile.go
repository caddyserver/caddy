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
	httpcaddyfile.RegisterHandlerDirective("request_header", parseReqHdrCaddyfile)
}

// parseCaddyfile sets up the handler for response headers from
// Caddyfile tokens. Syntax:
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
			var value string
			if h.NextArg() {
				value = h.Val()
			}
			processCaddyfileLineRespHdr(hdr, field, value)
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
			processCaddyfileLineRespHdr(hdr, field, value)
		}
	}
	return hdr, nil
}

// parseReqHdrCaddyfile sets up the handler for request headers
// from Caddyfile tokens. Syntax:
//
//     request_header [<matcher>] [[+|-]<field> <value>]
//
func parseReqHdrCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	hdr := new(Headers)
	for h.Next() {
		if !h.NextArg() {
			return nil, h.ArgErr()
		}
		field := h.Val()
		var value string
		if h.NextArg() {
			value = h.Val()
		}

		if hdr.Request == nil {
			hdr.Request = new(HeaderOps)
		}
		if strings.HasPrefix(field, "+") {
			if hdr.Request.Add == nil {
				hdr.Request.Add = make(http.Header)
			}
			hdr.Request.Add.Set(field[1:], value)
		} else if strings.HasPrefix(field, "-") {
			hdr.Request.Delete = append(hdr.Request.Delete, field[1:])
		} else {
			if hdr.Request.Set == nil {
				hdr.Request.Set = make(http.Header)
			}
			hdr.Request.Set.Set(field, value)
		}

		if h.NextArg() {
			return nil, h.ArgErr()
		}
	}
	return hdr, nil
}

func processCaddyfileLineRespHdr(hdr *Headers, field, value string) {
	if hdr.Response == nil {
		hdr.Response = &RespHeaderOps{
			HeaderOps: new(HeaderOps),
			Deferred:  true,
		}
	}
	if strings.HasPrefix(field, "+") {
		if hdr.Response.Add == nil {
			hdr.Response.Add = make(http.Header)
		}
		hdr.Response.Add.Set(field[1:], value)
	} else if strings.HasPrefix(field, "-") {
		hdr.Response.Delete = append(hdr.Response.Delete, field[1:])
	} else {
		if hdr.Response.Set == nil {
			hdr.Response.Set = make(http.Header)
		}
		hdr.Response.Set.Set(field, value)
	}
}
