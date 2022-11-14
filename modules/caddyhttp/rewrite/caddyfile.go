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

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("rewrite", parseCaddyfileRewrite)
	httpcaddyfile.RegisterHandlerDirective("method", parseCaddyfileMethod)
	httpcaddyfile.RegisterHandlerDirective("uri", parseCaddyfileURI)
	httpcaddyfile.RegisterDirective("handle_path", parseCaddyfileHandlePath)
}

// parseCaddyfileRewrite sets up a basic rewrite handler from Caddyfile tokens. Syntax:
//
//	rewrite [<matcher>] <to>
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

// parseCaddyfileMethod sets up a basic method rewrite handler from Caddyfile tokens. Syntax:
//
//	method [<matcher>] <method>
func parseCaddyfileMethod(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var rewr Rewrite
	for h.Next() {
		if !h.NextArg() {
			return nil, h.ArgErr()
		}
		rewr.Method = h.Val()
		if h.NextArg() {
			return nil, h.ArgErr()
		}
	}
	return rewr, nil
}

// parseCaddyfileURI sets up a handler for manipulating (but not "rewriting") the
// URI from Caddyfile tokens. Syntax:
//
//	uri [<matcher>] strip_prefix|strip_suffix|replace|path_regexp <target> [<replacement> [<limit>]]
//
// If strip_prefix or strip_suffix are used, then <target> will be stripped
// only if it is the beginning or the end, respectively, of the URI path. If
// replace is used, then <target> will be replaced with <replacement> across
// the whole URI, up to <limit> times (or unlimited if unspecified). If
// path_regexp is used, then regular expression replacements will be performed
// on the path portion of the URI (and a limit cannot be set).
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

			rewr.URISubstring = append(rewr.URISubstring, substrReplacer{
				Find:    find,
				Replace: replace,
				Limit:   limInt,
			})
		case "path_regexp":
			if len(args) != 3 {
				return nil, h.ArgErr()
			}
			find, replace := args[1], args[2]
			rewr.PathRegexp = append(rewr.PathRegexp, &regexReplacer{
				Find:    find,
				Replace: replace,
			})
		default:
			return nil, h.Errf("unrecognized URI manipulation '%s'", args[0])
		}
	}
	return rewr, nil
}

// parseCaddyfileHandlePath parses the handle_path directive. Syntax:
//
//	handle_path [<matcher>] {
//	    <directives...>
//	}
//
// Only path matchers (with a `/` prefix) are supported as this is a shortcut
// for the handle directive with a strip_prefix rewrite.
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
		return nil, h.Errf("path matcher must begin with '/', got %s", path)
	}

	// we only want to strip what comes before the '/' if
	// the user specified it (e.g. /api/* should only strip /api)
	var stripPath string
	if strings.HasSuffix(path, "/*") {
		stripPath = path[:len(path)-2]
	} else if strings.HasSuffix(path, "*") {
		stripPath = path[:len(path)-1]
	} else {
		stripPath = path
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

	// make a matcher on the path and everything below it
	pathMatcher := caddy.ModuleMap{
		"path": h.JSON(caddyhttp.MatchPath{path}),
	}

	// build a route with a rewrite handler to strip the path prefix
	route := caddyhttp.Route{
		HandlersRaw: []json.RawMessage{
			caddyconfig.JSONModuleObject(Rewrite{
				StripPathPrefix: stripPath,
			}, "handler", "rewrite", nil),
		},
	}

	// prepend the route to the subroute
	subroute.Routes = append([]caddyhttp.Route{route}, subroute.Routes...)

	// build and return a route from the subroute
	return h.NewRoute(pathMatcher, subroute), nil
}
