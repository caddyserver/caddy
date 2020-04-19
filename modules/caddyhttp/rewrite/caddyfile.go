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
	"encoding/json"
	"strconv"
	"strings"
	"fmt"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("rewrite", parseCaddyfileRewrite)
	httpcaddyfile.RegisterHandlerDirective("uri", parseCaddyfileURI)
	httpcaddyfile.RegisterDirective("handle_path", parseCaddyfileHandlePath)
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

// parseCaddyfileURI sets up a handler for manipulating (but not "rewriting") the
// URI from Caddyfile tokens. Syntax:
//
//     uri [<matcher>] strip_prefix|strip_suffix|replace <target> [<replacement> [<limit>]]
//
// If strip_prefix or strip_suffix are used, then <target> will be stripped
// only if it is the beginning or the end, respectively, of the URI path. If
// replace is used, then <target> will be replaced with <replacement> across
// the whole URI, up to <limit> times (or unlimited if unspecified).
func parseCaddyfileURI(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var rewr Rewrite
	for h.Next() {
		args := h.RemainingArgs()
		if len(args) < 2 {
			return nil, h.ArgErr()
		}
		switch args[0] {
		case "strip_prefix":
			if len(args) > 2 {
				return nil, h.ArgErr()
			}
			rewr.StripPathPrefix = args[1]
			if !strings.HasPrefix(rewr.StripPathPrefix, "/") {
				rewr.StripPathPrefix = "/" + rewr.StripPathPrefix
			}
		case "strip_suffix":
			if len(args) > 2 {
				return nil, h.ArgErr()
			}
			rewr.StripPathSuffix = args[1]
		case "replace":
			var find, replace, lim string
			switch len(args) {
			case 4:
				lim = args[3]
				fallthrough
			case 3:
				find = args[1]
				replace = args[2]
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

			rewr.URISubstring = append(rewr.URISubstring, replacer{
				Find:    find,
				Replace: replace,
				Limit:   limInt,
			})
		default:
			return nil, h.Errf("unrecognized URI manipulation '%s'", args[0])
		}
	}
	return rewr, nil
}

func parseCaddyfileHandlePath(h httpcaddyfile.Helper) ([]httpcaddyfile.ConfigValue, error) {
	if !h.Next() {
		return nil, h.ArgErr()
	}
	if !h.NextArg() {
		return nil, h.ArgErr()
	}

	// read the prefix to strip
	path := h.Val()
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	// the ParseSegmentAsSubroute function expects the cursor
	// to be at the token just before the block opening,
	// so we need to rewind because we already read past it
	h.Reset()
	h.Next()

	// parse the block contents as a subroute handler
	handler, err := httpcaddyfile.ParseSegmentAsSubroute(h)
	if err != nil {
		return nil, err
	}
	subroute, ok := handler.(*caddyhttp.Subroute)
	if !ok {
		return nil, h.Errf("segment was not parsed as a subroute")
	}

	// build a rewrite handler to strip the path prefix
	rewriteHandler := Rewrite{
		StripPathPrefix: path,
	}
	route := caddyhttp.Route{
		HandlersRaw: []json.RawMessage{caddyconfig.JSONModuleObject(rewriteHandler, "handler", "rewrite", nil)},
	}

	fmt.Printf("%+v\n", handler)
	fmt.Printf("%+v\n", subroute)

	// prepend the route to the subroute
	subroute.Routes = append([]caddyhttp.Route{route}, subroute.Routes...)

	fmt.Printf("%+v\n", subroute)

	return []httpcaddyfile.ConfigValue{
		{
			Class: "route",
			Value: *subroute,
		},
	}, nil
}