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
	"strconv"

	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("rewrite", parseCaddyfileRewrite)
	httpcaddyfile.RegisterHandlerDirective("strip_prefix", parseCaddyfileStripPrefix)
	httpcaddyfile.RegisterHandlerDirective("strip_suffix", parseCaddyfileStripSuffix)
	httpcaddyfile.RegisterHandlerDirective("uri_replace", parseCaddyfileURIReplace)
}

// parseCaddyfileRewrite sets up a basic rewrite handler from Caddyfile tokens. Syntax:
//
//     rewrite [<matcher>] <to>
//
// Only URI components which are given in <to> will be set in the resulting URI.
// See the docs for the rewrite handler for more information.
func parseCaddyfileRewrite(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var rewr Rewrite
	for h.Next() {
		if !h.NextArg() {
			return nil, h.ArgErr()
		}
		rewr.URI = h.Val()
		if h.NextArg() {
			return nil, h.ArgErr()
		}
	}
	return rewr, nil
}

// parseCaddyfileStripPrefix sets up a handler from Caddyfile tokens. Syntax:
//
//     strip_prefix [<matcher>] <prefix>
//
// The request path will be stripped the given prefix.
func parseCaddyfileStripPrefix(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var rewr Rewrite
	for h.Next() {
		if !h.NextArg() {
			return nil, h.ArgErr()
		}
		rewr.StripPathPrefix = h.Val()
		if h.NextArg() {
			return nil, h.ArgErr()
		}
	}
	return rewr, nil
}

// parseCaddyfileStripSuffix sets up a handler from Caddyfile tokens. Syntax:
//
//     strip_suffix [<matcher>] <suffix>
//
// The request path will be stripped the given suffix.
func parseCaddyfileStripSuffix(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var rewr Rewrite
	for h.Next() {
		if !h.NextArg() {
			return nil, h.ArgErr()
		}
		rewr.StripPathSuffix = h.Val()
		if h.NextArg() {
			return nil, h.ArgErr()
		}
	}
	return rewr, nil
}

// parseCaddyfileURIReplace sets up a handler from Caddyfile tokens. Syntax:
//
//     uri_replace [<matcher>] <find> <replace> [<limit>]
//
// Substring replacements will be performed on the request URI up to the
// number specified by limit, if any (default = 0, or no limit).
func parseCaddyfileURIReplace(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var rewr Rewrite

	var repls []replacer

	for h.Next() {
		args := h.RemainingArgs()
		var find, replace, lim string
		switch len(args) {
		case 3:
			lim = args[2]
			fallthrough
		case 2:
			find = args[0]
			replace = args[1]
		default:
			return nil, h.ArgErr()
		}

		var limInt int
		if lim != "" {
			var err error
			limInt, err = strconv.Atoi(lim)
			if err != nil {
				return nil, h.Errf("limit must be an integer; invalid: %v", err)
			}
		}

		repls = append(repls, replacer{
			Find:    find,
			Replace: replace,
			Limit:   limInt,
		})
	}

	rewr.URISubstring = repls

	return rewr, nil
}
