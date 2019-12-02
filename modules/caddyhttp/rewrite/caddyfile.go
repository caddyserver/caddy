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

package rewrite

import (
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("rewrite", parseCaddyfile)
}

// parseCaddyfile sets up the handler from Caddyfile tokens. Syntax:
//
//     rewrite [<matcher>] [<uri>] {
//         uri                <string>
//         method            <string>
//         strip_path_prefix <string>
//         strip_path_suffix <string>
//         rehandle          <bool>
//         http_redirect     <status_code>
//     }
//
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var (
		rewr Rewrite

		uriIsSet       bool
		nextBlockIsSet bool
		rehandleIsSet  bool
		redirectIsSet  bool
	)

	for h.Next() {
		args := h.RemainingArgs()
		switch len(args) {
		case 0:
		case 1:
			uriIsSet = true
			rewr.URI = h.Val()
		default:
			return nil, h.ArgErr()
		}

		for h.NextBlock(0) {
			nextBlockIsSet = true
			switch h.Val() {
			case "uri":
				if uriIsSet {
					return nil, h.Err("uri is already set")
				}
				if !h.Args(&rewr.URI) {
					return nil, h.ArgErr()
				}
			case "method":
				if !h.Args(&rewr.Method) {
					return nil, h.ArgErr()
				}
			case "strip_prefix":
				if !h.Args(&rewr.StripPathPrefix) {
					return nil, h.ArgErr()
				}
			case "strip_suffix":
				if !h.Args(&rewr.StripPathSuffix) {
					return nil, h.ArgErr()
				}
			case "rehandle":
				rehandleIsSet = true
				if redirectIsSet {
					return nil, h.Err("http_redirect is already set")
				}

				var rehandle string
				if !h.Args(&rehandle) {
					return nil, h.ArgErr()
				}

				switch rehandle {
				case "true":
					rewr.Rehandle = true
				case "false":
				default:
					return nil, h.Errf("invalid rehandle argument '%s', expected bool", rehandle)
				}
			case "http_redirect":
				redirectIsSet = true
				if rehandleIsSet {
					return nil, h.Err("rehandle is already set")
				}

				var status string
				if !h.Args(&status) {
					return nil, h.ArgErr()
				}

				rewr.HTTPRedirect = caddyhttp.WeakString(status)
			default:
				return nil, h.Errf("unknown subdirective '%s'", h.Val())
			}
		}

		if !uriIsSet && !nextBlockIsSet {
			return nil, h.Err("must provide 'uri' or subdirectives")
		}
	}
	if !rehandleIsSet && !redirectIsSet {
		rewr.Rehandle = true
	}
	return rewr, nil
}
