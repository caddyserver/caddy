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
	"strconv"
	"strings"

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
//	transport fastcgi {
//	    root <path>
//	    split <at>
//	    env <key> <value>
//	    resolve_root_symlink
//	    dial_timeout <duration>
//	    read_timeout <duration>
//	    write_timeout <duration>
//	    capture_stderr
//	}
func (t *Transport) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume transport name
	for d.NextBlock(0) {
		switch d.Val() {
		case "root":
			if !d.NextArg() {
				return d.ArgErr()
			}
			t.Root = d.Val()

		case "split":
			t.SplitPath = d.RemainingArgs()
			if len(t.SplitPath) == 0 {
				return d.ArgErr()
			}

		case "env":
			args := d.RemainingArgs()
			if len(args) != 2 {
				return d.ArgErr()
			}
			if t.EnvVars == nil {
				t.EnvVars = make(map[string]string)
			}
			t.EnvVars[args[0]] = args[1]

		case "resolve_root_symlink":
			if d.NextArg() {
				return d.ArgErr()
			}
			t.ResolveRootSymlink = true

		case "dial_timeout":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("bad timeout value %s: %v", d.Val(), err)
			}
			t.DialTimeout = caddy.Duration(dur)

		case "read_timeout":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("bad timeout value %s: %v", d.Val(), err)
			}
			t.ReadTimeout = caddy.Duration(dur)

		case "write_timeout":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("bad timeout value %s: %v", d.Val(), err)
			}
			t.WriteTimeout = caddy.Duration(dur)

		case "capture_stderr":
			if d.NextArg() {
				return d.ArgErr()
			}
			t.CaptureStderr = true

		default:
			return d.Errf("unrecognized subdirective %s", d.Val())
		}
	}
	return nil
}

// parsePHPFastCGI parses the php_fastcgi directive, which has the same syntax
// as the reverse_proxy directive (in fact, the reverse_proxy's directive
// Unmarshaler is invoked by this function) but the resulting proxy is specially
// configured for most™️ PHP apps over FastCGI. A line such as this:
//
//	php_fastcgi localhost:7777
//
// is equivalent to a route consisting of:
//
//	# Add trailing slash for directory requests
//	# This redirection is automatically disabled if "{http.request.uri.path}/index.php"
//	# doesn't appear in the try_files list
//	@canonicalPath {
//	    file {path}/index.php
//	    not path */
//	}
//	redir @canonicalPath {path}/ 308
//
//	# If the requested file does not exist, try index files and assume index.php always exists
//	@indexFiles file {
//	    try_files {path} {path}/index.php index.php
//	    try_policy first_exist_fallback
//	    split_path .php
//	}
//	rewrite @indexFiles {http.matchers.file.relative}
//
//	# Proxy PHP files to the FastCGI responder
//	@phpFiles path *.php
//	reverse_proxy @phpFiles localhost:7777 {
//	    transport fastcgi {
//	        split .php
//	    }
//	}
//
// Thus, this directive produces multiple handlers, each with a different
// matcher because multiple consecutive handlers are necessary to support
// the common PHP use case. If this "common" config is not compatible
// with a user's PHP requirements, they can use a manual approach based
// on the example above to configure it precisely as they need.
//
// If a matcher is specified by the user, for example:
//
//	php_fastcgi /subpath localhost:7777
//
// then the resulting handlers are wrapped in a subroute that uses the
// user's matcher as a prerequisite to enter the subroute. In other
// words, the directive's matcher is necessary, but not sufficient.
func parsePHPFastCGI(h httpcaddyfile.Helper) ([]httpcaddyfile.ConfigValue, error) {
	if !h.Next() {
		return nil, h.ArgErr()
	}

	// set up the transport for FastCGI, and specifically PHP
	fcgiTransport := Transport{}

	// set up the set of file extensions allowed to execute PHP code
	extensions := []string{".php"}

	// set the default index file for the try_files rewrites
	indexFile := "index.php"

	// set up for explicitly overriding try_files
	var tryFiles []string

	// if the user specified a matcher token, use that
	// matcher in a route that wraps both of our routes;
	// either way, strip the matcher token and pass
	// the remaining tokens to the unmarshaler so that
	// we can gain the rest of the reverse_proxy syntax
	userMatcherSet, err := h.ExtractMatcherSet()
	if err != nil {
		return nil, err
	}

	// make a new dispenser from the remaining tokens so that we
	// can reset the dispenser back to this point for the
	// reverse_proxy unmarshaler to read from it as well
	dispenser := h.NewFromNextSegment()

	// read the subdirectives that we allow as overrides to
	// the php_fastcgi shortcut
	// NOTE: we delete the tokens as we go so that the reverse_proxy
	// unmarshal doesn't see these subdirectives which it cannot handle
	for dispenser.Next() {
		for dispenser.NextBlock(0) {
			// ignore any sub-subdirectives that might
			// have the same name somewhere within
			// the reverse_proxy passthrough tokens
			if dispenser.Nesting() != 1 {
				continue
			}

			// parse the php_fastcgi subdirectives
			switch dispenser.Val() {
			case "root":
				if !dispenser.NextArg() {
					return nil, dispenser.ArgErr()
				}
				fcgiTransport.Root = dispenser.Val()
				dispenser.DeleteN(2)

			case "split":
				extensions = dispenser.RemainingArgs()
				dispenser.DeleteN(len(extensions) + 1)
				if len(extensions) == 0 {
					return nil, dispenser.ArgErr()
				}

			case "env":
				args := dispenser.RemainingArgs()
				dispenser.DeleteN(len(args) + 1)
				if len(args) != 2 {
					return nil, dispenser.ArgErr()
				}
				if fcgiTransport.EnvVars == nil {
					fcgiTransport.EnvVars = make(map[string]string)
				}
				fcgiTransport.EnvVars[args[0]] = args[1]

			case "index":
				args := dispenser.RemainingArgs()
				dispenser.DeleteN(len(args) + 1)
				if len(args) != 1 {
					return nil, dispenser.ArgErr()
				}
				indexFile = args[0]

			case "try_files":
				args := dispenser.RemainingArgs()
				dispenser.DeleteN(len(args) + 1)
				if len(args) < 1 {
					return nil, dispenser.ArgErr()
				}
				tryFiles = args

			case "resolve_root_symlink":
				args := dispenser.RemainingArgs()
				dispenser.DeleteN(len(args) + 1)
				fcgiTransport.ResolveRootSymlink = true

			case "dial_timeout":
				if !dispenser.NextArg() {
					return nil, dispenser.ArgErr()
				}
				dur, err := caddy.ParseDuration(dispenser.Val())
				if err != nil {
					return nil, dispenser.Errf("bad timeout value %s: %v", dispenser.Val(), err)
				}
				fcgiTransport.DialTimeout = caddy.Duration(dur)
				dispenser.DeleteN(2)

			case "read_timeout":
				if !dispenser.NextArg() {
					return nil, dispenser.ArgErr()
				}
				dur, err := caddy.ParseDuration(dispenser.Val())
				if err != nil {
					return nil, dispenser.Errf("bad timeout value %s: %v", dispenser.Val(), err)
				}
				fcgiTransport.ReadTimeout = caddy.Duration(dur)
				dispenser.DeleteN(2)

			case "write_timeout":
				if !dispenser.NextArg() {
					return nil, dispenser.ArgErr()
				}
				dur, err := caddy.ParseDuration(dispenser.Val())
				if err != nil {
					return nil, dispenser.Errf("bad timeout value %s: %v", dispenser.Val(), err)
				}
				fcgiTransport.WriteTimeout = caddy.Duration(dur)
				dispenser.DeleteN(2)

			case "capture_stderr":
				args := dispenser.RemainingArgs()
				dispenser.DeleteN(len(args) + 1)
				fcgiTransport.CaptureStderr = true
			}
		}
	}

	// reset the dispenser after we're done so that the reverse_proxy
	// unmarshaler can read it from the start
	dispenser.Reset()

	// set up a route list that we'll append to
	routes := caddyhttp.RouteList{}

	// set the list of allowed path segments on which to split
	fcgiTransport.SplitPath = extensions

	// if the index is turned off, we skip the redirect and try_files
	if indexFile != "off" {
		dirRedir := false
		dirIndex := "{http.request.uri.path}/" + indexFile
		tryPolicy := "first_exist_fallback"

		// if tryFiles wasn't overridden, use a reasonable default
		if len(tryFiles) == 0 {
			tryFiles = []string{"{http.request.uri.path}", dirIndex, indexFile}
			dirRedir = true
		} else {
			if !strings.HasSuffix(tryFiles[len(tryFiles)-1], ".php") {
				// use first_exist strategy if the last file is not a PHP file
				tryPolicy = ""
			}

			for _, tf := range tryFiles {
				if tf == dirIndex {
					dirRedir = true

					break
				}
			}
		}

		if dirRedir {
			// route to redirect to canonical path if index PHP file
			redirMatcherSet := caddy.ModuleMap{
				"file": h.JSON(fileserver.MatchFile{
					TryFiles: []string{dirIndex},
				}),
				"not": h.JSON(caddyhttp.MatchNot{
					MatcherSetsRaw: []caddy.ModuleMap{
						{
							"path": h.JSON(caddyhttp.MatchPath{"*/"}),
						},
					},
				}),
			}
			redirHandler := caddyhttp.StaticResponse{
				StatusCode: caddyhttp.WeakString(strconv.Itoa(http.StatusPermanentRedirect)),
				Headers:    http.Header{"Location": []string{"{http.request.orig_uri.path}/{http.request.orig_uri.prefixed_query}"}},
			}
			redirRoute := caddyhttp.Route{
				MatcherSetsRaw: []caddy.ModuleMap{redirMatcherSet},
				HandlersRaw:    []json.RawMessage{caddyconfig.JSONModuleObject(redirHandler, "handler", "static_response", nil)},
			}

			routes = append(routes, redirRoute)
		}

		// route to rewrite to PHP index file
		rewriteMatcherSet := caddy.ModuleMap{
			"file": h.JSON(fileserver.MatchFile{
				TryFiles:  tryFiles,
				TryPolicy: tryPolicy,
				SplitPath: extensions,
			}),
		}
		rewriteHandler := rewrite.Rewrite{
			URI: "{http.matchers.file.relative}",
		}
		rewriteRoute := caddyhttp.Route{
			MatcherSetsRaw: []caddy.ModuleMap{rewriteMatcherSet},
			HandlersRaw:    []json.RawMessage{caddyconfig.JSONModuleObject(rewriteHandler, "handler", "rewrite", nil)},
		}

		routes = append(routes, rewriteRoute)
	}

	// route to actually reverse proxy requests to PHP files;
	// match only requests that are for PHP files
	pathList := []string{}
	for _, ext := range extensions {
		pathList = append(pathList, "*"+ext)
	}
	rpMatcherSet := caddy.ModuleMap{
		"path": h.JSON(pathList),
	}

	// create the reverse proxy handler which uses our FastCGI transport
	rpHandler := &reverseproxy.Handler{
		TransportRaw: caddyconfig.JSONModuleObject(fcgiTransport, "protocol", "fastcgi", nil),
	}

	// the rest of the config is specified by the user
	// using the reverse_proxy directive syntax
	dispenser.Next() // consume the directive name
	err = rpHandler.UnmarshalCaddyfile(dispenser)
	if err != nil {
		return nil, err
	}
	err = rpHandler.FinalizeUnmarshalCaddyfile(h)
	if err != nil {
		return nil, err
	}

	// create the final reverse proxy route which is
	// conditional on matching PHP files
	rpRoute := caddyhttp.Route{
		MatcherSetsRaw: []caddy.ModuleMap{rpMatcherSet},
		HandlersRaw:    []json.RawMessage{caddyconfig.JSONModuleObject(rpHandler, "handler", "reverse_proxy", nil)},
	}

	subroute := caddyhttp.Subroute{
		Routes: append(routes, rpRoute),
	}

	// the user's matcher is a prerequisite for ours, so
	// wrap ours in a subroute and return that
	if userMatcherSet != nil {
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

	// otherwise, return the literal subroute instead of
	// individual routes, to ensure they stay together and
	// are treated as a single unit, without necessarily
	// creating an actual subroute in the output
	return []httpcaddyfile.ConfigValue{
		{
			Class: "route",
			Value: subroute,
		},
	}, nil
}
