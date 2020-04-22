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

package fileserver

import (
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/rewrite"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("file_server", parseCaddyfile)
	httpcaddyfile.RegisterDirective("try_files", parseTryFiles)
}

// parseCaddyfile parses the file_server directive. It enables the static file
// server and configures it with this syntax:
//
//    file_server [<matcher>] [browse] {
//        root   <path>
//	      hide   <files...>
//	      index  <files...>
//	      browse [<template_file>]
//    }
//
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var fsrv FileServer

	for h.Next() {
		args := h.RemainingArgs()
		switch len(args) {
		case 0:
		case 1:
			if args[0] != "browse" {
				return nil, h.ArgErr()
			}
			fsrv.Browse = new(Browse)
		default:
			return nil, h.ArgErr()
		}

		for h.NextBlock(0) {
			switch h.Val() {
			case "hide":
				fsrv.Hide = h.RemainingArgs()
				if len(fsrv.Hide) == 0 {
					return nil, h.ArgErr()
				}
			case "index":
				fsrv.IndexNames = h.RemainingArgs()
				if len(fsrv.IndexNames) == 0 {
					return nil, h.ArgErr()
				}
			case "root":
				if !h.Args(&fsrv.Root) {
					return nil, h.ArgErr()
				}
			case "browse":
				if fsrv.Browse != nil {
					return nil, h.Err("browsing is already configured")
				}
				fsrv.Browse = new(Browse)
				h.Args(&fsrv.Browse.TemplateFile)
			default:
				return nil, h.Errf("unknown subdirective '%s'", h.Val())
			}
		}
	}

	// hide the Caddyfile (and any imported Caddyfiles)
	if configFiles := h.Caddyfiles(); len(configFiles) > 0 {
		for _, file := range configFiles {
			if !fileHidden(file, fsrv.Hide) {
				fsrv.Hide = append(fsrv.Hide, file)
			}
		}
	}

	return &fsrv, nil
}

// parseTryFiles parses the try_files directive. It combines a file matcher
// with a rewrite directive, so this is not a standard handler directive.
// A try_files directive has this syntax (notice no matcher tokens accepted):
//
//    try_files <files...>
//
// and is basically shorthand for:
//
//    @try_files {
//        file {
//            try_files <files...>
//        }
//    }
//    rewrite @try_files {http.matchers.file.relative}
//
// This directive rewrites request paths only, preserving any other part
// of the URI, unless the part is explicitly given in the file list. For
// example, if any of the files in the list have a query string:
//
//    try_files {path} index.php?{query}&p={path}
//
// then the query string will not be treated as part of the file name; and
// if that file matches, the given query string will replace any query string
// that already exists on the request URI.
func parseTryFiles(h httpcaddyfile.Helper) ([]httpcaddyfile.ConfigValue, error) {
	if !h.Next() {
		return nil, h.ArgErr()
	}

	tryFiles := h.RemainingArgs()
	if len(tryFiles) == 0 {
		return nil, h.ArgErr()
	}

	// makeRoute returns a route that tries the files listed in try
	// and then rewrites to the matched file; userQueryString is
	// appended to the rewrite rule.
	makeRoute := func(try []string, userQueryString string) []httpcaddyfile.ConfigValue {
		handler := rewrite.Rewrite{
			URI: "{http.matchers.file.relative}" + userQueryString,
		}
		matcherSet := caddy.ModuleMap{
			"file": h.JSON(MatchFile{TryFiles: try}),
		}
		return h.NewRoute(matcherSet, handler)
	}

	var result []httpcaddyfile.ConfigValue

	// if there are query strings in the list, we have to split into
	// a separate route for each item with a query string, because
	// the rewrite is different for that item
	try := make([]string, 0, len(tryFiles))
	for _, item := range tryFiles {
		if idx := strings.Index(item, "?"); idx >= 0 {
			if len(try) > 0 {
				result = append(result, makeRoute(try, "")...)
				try = []string{}
			}
			result = append(result, makeRoute([]string{item[:idx]}, item[idx:])...)
			continue
		}
		// accumulate consecutive non-query-string parameters
		try = append(try, item)
	}
	if len(try) > 0 {
		result = append(result, makeRoute(try, "")...)
	}

	// ensure that multiple routes (possible if rewrite targets
	// have query strings, for example) are grouped together
	// so only the first matching rewrite is performed (#2891)
	h.GroupRoutes(result)

	return result, nil
}
