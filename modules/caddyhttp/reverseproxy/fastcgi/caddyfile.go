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

package fastcgi

import (
	"encoding/json"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/fileserver"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/rewrite"
)

func init() {
	httpcaddyfile.RegisterDirective("php_fastcgi", parsePHPFastCGI)
}

// UnmarshalCaddyfile deserializes Caddyfile tokens into h.
//
//     transport fastcgi {
//         root <path>
//         split <at>
//         env <key> <value>
//     }
//
func (t *Transport) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "root":
				if !d.NextArg() {
					return d.ArgErr()
				}
				t.Root = d.Val()

			case "split":
				if !d.NextArg() {
					return d.ArgErr()
				}
				t.SplitPath = d.Val()

			case "env":
				args := d.RemainingArgs()
				if len(args) != 2 {
					return d.ArgErr()
				}
				if t.EnvVars == nil {
					t.EnvVars = make(map[string]string)
				}
				t.EnvVars[args[0]] = args[1]

			default:
				return d.Errf("unrecognized subdirective %s", d.Val())
			}
		}
	}
	return nil
}

// parsePHPFastCGI parses the php_fastcgi directive, which has the same syntax
// as the reverse_proxy directive (in fact, the reverse_proxy's directive
// Unmarshaler is invoked by this function) but the resulting proxy is specially
// configured for most™️ PHP apps over FastCGI. A line such as this:
//
//     php_fastcgi localhost:7777
//
// is equivalent to:
//
//     @canonicalPath {
//         file {
//             try_files {path}/index.php
//         }
//         not {
//             path */
//         }
//     }
//     redir @canonicalPath {path}/ 308
//
//     try_files {path} {path}/index.php index.php
//
//     @phpFiles {
//         path *.php
//     }
//     reverse_proxy @phpFiles localhost:7777 {
//         transport fastcgi {
//             split .php
//         }
//     }
//
// Thus, this directive produces multiple routes, each with a different
// matcher because multiple consecutive routes are necessary to support
// the common PHP use case. If this "common" config is not compatible
// with a user's PHP requirements, they can use a manual approach based
// on the example above to configure it precisely as they need.
//
// If a matcher is specified by the user, for example:
//
//     php_fastcgi /subpath localhost:7777
//
// then the resulting routes are wrapped in a subroute that uses the
// user's matcher as a prerequisite to enter the subroute. In other
// words, the directive's matcher is necessary, but not sufficient.
func parsePHPFastCGI(h httpcaddyfile.Helper) ([]httpcaddyfile.ConfigValue, error) {
	if !h.Next() {
		return nil, h.ArgErr()
	}

	// route to redirect to canonical path if index PHP file
	redirMatcherSet := caddy.ModuleMap{
		"file": h.JSON(fileserver.MatchFile{
			TryFiles: []string{"{http.request.uri.path}/index.php"},
		}),
		"not": h.JSON(caddyhttp.MatchNegate{
			MatchersRaw: caddy.ModuleMap{
				"path": h.JSON(caddyhttp.MatchPath{"*/"}),
			},
		}),
	}
	redirHandler := caddyhttp.StaticResponse{
		StatusCode: caddyhttp.WeakString("308"),
		Headers:    http.Header{"Location": []string{"{http.request.uri.path}/"}},
	}
	redirRoute := caddyhttp.Route{
		MatcherSetsRaw: []caddy.ModuleMap{redirMatcherSet},
		HandlersRaw:    []json.RawMessage{caddyconfig.JSONModuleObject(redirHandler, "handler", "static_response", nil)},
	}

	// route to rewrite to PHP index file
	rewriteMatcherSet := caddy.ModuleMap{
		"file": h.JSON(fileserver.MatchFile{
			TryFiles: []string{"{http.request.uri.path}", "{http.request.uri.path}/index.php", "index.php"},
		}),
	}
	rewriteHandler := rewrite.Rewrite{
		URI: "{http.matchers.file.relative}{http.request.uri.query_string}",
	}
	rewriteRoute := caddyhttp.Route{
		MatcherSetsRaw: []caddy.ModuleMap{rewriteMatcherSet},
		HandlersRaw:    []json.RawMessage{caddyconfig.JSONModuleObject(rewriteHandler, "handler", "rewrite", nil)},
	}

	// route to actually reverse proxy requests to PHP files;
	// match only requests that are for PHP files
	rpMatcherSet := caddy.ModuleMap{
		"path": h.JSON([]string{"*.php"}),
	}

	// if the user specified a matcher token, use that
	// matcher in a route that wraps both of our routes;
	// either way, strip the matcher token and pass
	// the remaining tokens to the unmarshaler so that
	// we can gain the rest of the reverse_proxy syntax
	userMatcherSet, hasUserMatcher, err := h.MatcherToken()
	if err != nil {
		return nil, err
	}
	if hasUserMatcher {
		h.Dispenser.Delete() // strip matcher token
	}
	h.Dispenser.Reset() // pretend this lookahead never happened

	// set up the transport for FastCGI, and specifically PHP
	fcgiTransport := Transport{SplitPath: ".php"}

	// create the reverse proxy handler which uses our FastCGI transport
	rpHandler := &reverseproxy.Handler{
		TransportRaw: caddyconfig.JSONModuleObject(fcgiTransport, "protocol", "fastcgi", nil),
	}

	// the rest of the config is specified by the user
	// using the reverse_proxy directive syntax
	err = rpHandler.UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		return nil, err
	}

	// create the final reverse proxy route which is
	// conditional on matching PHP files
	rpRoute := caddyhttp.Route{
		MatcherSetsRaw: []caddy.ModuleMap{rpMatcherSet},
		HandlersRaw:    []json.RawMessage{caddyconfig.JSONModuleObject(rpHandler, "handler", "reverse_proxy", nil)},
	}

	// the user's matcher is a prerequisite for ours, so
	// wrap ours in a subroute and return that
	if hasUserMatcher {
		subroute := caddyhttp.Subroute{
			Routes: caddyhttp.RouteList{redirRoute, rewriteRoute, rpRoute},
		}
		return []httpcaddyfile.ConfigValue{
			{
				Class: "route",
				Value: caddyhttp.Route{
					MatcherSetsRaw: []caddy.ModuleMap{userMatcherSet},
					HandlersRaw:    []json.RawMessage{caddyconfig.JSONModuleObject(subroute, "handler", "subroute", nil)},
				},
			},
		}, nil
	}

	// if the user did not specify a matcher, then
	// we can just use our own matchers
	return []httpcaddyfile.ConfigValue{
		{
			Class: "route",
			Value: redirRoute,
		},
		{
			Class: "route",
			Value: rewriteRoute,
		},
		{
			Class: "route",
			Value: rpRoute,
		},
	}, nil
}
