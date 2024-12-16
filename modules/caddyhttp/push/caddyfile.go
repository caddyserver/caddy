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

package push

import (
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/headers"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("push", parseCaddyfile)
}

// parseCaddyfile sets up the push handler. Syntax:
//
//	push [<matcher>] [<resource>] {
//	    [GET|HEAD] <resource>
//	    headers {
//	        [+]<field> [<value|regexp> [<replacement>]]
//	        -<field>
//	    }
//	}
//
// A single resource can be specified inline without opening a
// block for the most common/simple case. Or, a block can be
// opened and multiple resources can be specified, one per
// line, optionally preceded by the method. The headers
// subdirective can be used to customize the headers that
// are set on each (synthetic) push request, using the same
// syntax as the 'header' directive for request headers.
// Placeholders are accepted in resource and header field
// name and value and replacement tokens.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	h.Next() // consume directive name

	handler := new(Handler)

	// inline resources
	if h.NextArg() {
		handler.Resources = append(handler.Resources, Resource{Target: h.Val()})
	}

	// optional block
	for h.NextBlock(0) {
		switch h.Val() {
		case "headers":
			if h.NextArg() {
				return nil, h.ArgErr()
			}
			for nesting := h.Nesting(); h.NextBlock(nesting); {
				var err error

				// include current token, which we treat as an argument here
				args := []string{h.Val()}
				args = append(args, h.RemainingArgs()...)

				if handler.Headers == nil {
					handler.Headers = new(HeaderConfig)
				}

				switch len(args) {
				case 1:
					err = headers.CaddyfileHeaderOp(&handler.Headers.HeaderOps, args[0], "", nil)
				case 2:
					err = headers.CaddyfileHeaderOp(&handler.Headers.HeaderOps, args[0], args[1], nil)
				case 3:
					err = headers.CaddyfileHeaderOp(&handler.Headers.HeaderOps, args[0], args[1], &args[2])
				default:
					return nil, h.ArgErr()
				}

				if err != nil {
					return nil, h.Err(err.Error())
				}
			}

		case "GET", "HEAD":
			method := h.Val()
			if !h.NextArg() {
				return nil, h.ArgErr()
			}
			target := h.Val()
			handler.Resources = append(handler.Resources, Resource{
				Method: method,
				Target: target,
			})

		default:
			handler.Resources = append(handler.Resources, Resource{Target: h.Val()})
		}
	}
	return handler, nil
}
