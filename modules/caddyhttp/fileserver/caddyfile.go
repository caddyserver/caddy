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
	"path/filepath"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/encode"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/rewrite"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("file_server", parseCaddyfile)
	httpcaddyfile.RegisterDirective("try_files", parseTryFiles)
}

// parseCaddyfile parses the file_server directive.
// See UnmarshalCaddyfile for the syntax.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	fsrv := new(FileServer)
	err := fsrv.UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		return fsrv, err
	}
	err = fsrv.FinalizeUnmarshalCaddyfile(h)
	if err != nil {
		return nil, err
	}
	return fsrv, err
}

// UnmarshalCaddyfile parses the file_server directive. It enables
// the static file server and configures it with this syntax:
//
//	file_server [<matcher>] [browse] {
//	    fs            <filesystem>
//	    root          <path>
//	    hide          <files...>
//	    index         <files...>
//	    browse        [<template_file>]
//	    precompressed <formats...>
//	    status        <status>
//	    disable_canonical_uris
//	}
//
// The FinalizeUnmarshalCaddyfile method should be called after this
// to finalize setup of hidden Caddyfiles.
func (fsrv *FileServer) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name

	args := d.RemainingArgs()
	switch len(args) {
	case 0:
	case 1:
		if args[0] != "browse" {
			return d.ArgErr()
		}
		fsrv.Browse = new(Browse)
	default:
		return d.ArgErr()
	}

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "fs":
			if !d.NextArg() {
				return d.ArgErr()
			}
			if fsrv.FileSystem != "" {
				return d.Err("file system already specified")
			}
			fsrv.FileSystem = d.Val()

		case "hide":
			fsrv.Hide = d.RemainingArgs()
			if len(fsrv.Hide) == 0 {
				return d.ArgErr()
			}

		case "index":
			fsrv.IndexNames = d.RemainingArgs()
			if len(fsrv.IndexNames) == 0 {
				return d.ArgErr()
			}

		case "root":
			if !d.Args(&fsrv.Root) {
				return d.ArgErr()
			}

		case "browse":
			if fsrv.Browse != nil {
				return d.Err("browsing is already configured")
			}
			fsrv.Browse = new(Browse)
			d.Args(&fsrv.Browse.TemplateFile)
			for nesting := d.Nesting(); d.NextBlock(nesting); {
				switch d.Val() {
				case "reveal_symlinks":
					if fsrv.Browse.RevealSymlinks {
						return d.Err("Symlinks path reveal is already enabled")
					}
					fsrv.Browse.RevealSymlinks = true
				case "sort":
					for d.NextArg() {
						dVal := d.Val()
						switch dVal {
						case sortByName, sortByNameDirFirst, sortBySize, sortByTime, sortOrderAsc, sortOrderDesc:
							fsrv.Browse.SortOptions = append(fsrv.Browse.SortOptions, dVal)
						default:
							return d.Errf("unknown sort option '%s'", dVal)
						}
					}
				case "file_limit":
					fileLimit := d.RemainingArgs()
					if len(fileLimit) != 1 {
						return d.Err("file_limit should have an integer value")
					}
					val, _ := strconv.Atoi(fileLimit[0])
					if fsrv.Browse.FileLimit != 0 {
						return d.Err("file_limit is already enabled")
					}
					fsrv.Browse.FileLimit = val
				default:
					return d.Errf("unknown subdirective '%s'", d.Val())
				}
			}

		case "precompressed":
			fsrv.PrecompressedOrder = d.RemainingArgs()
			if len(fsrv.PrecompressedOrder) == 0 {
				fsrv.PrecompressedOrder = []string{"br", "zstd", "gzip"}
			}

			for _, format := range fsrv.PrecompressedOrder {
				modID := "http.precompressed." + format
				mod, err := caddy.GetModule(modID)
				if err != nil {
					return d.Errf("getting module named '%s': %v", modID, err)
				}
				inst := mod.New()
				precompress, ok := inst.(encode.Precompressed)
				if !ok {
					return d.Errf("module %s is not a precompressor; is %T", modID, inst)
				}
				if fsrv.PrecompressedRaw == nil {
					fsrv.PrecompressedRaw = make(caddy.ModuleMap)
				}
				fsrv.PrecompressedRaw[format] = caddyconfig.JSON(precompress, nil)
			}

		case "status":
			if !d.NextArg() {
				return d.ArgErr()
			}
			fsrv.StatusCode = caddyhttp.WeakString(d.Val())

		case "disable_canonical_uris":
			if d.NextArg() {
				return d.ArgErr()
			}
			falseBool := false
			fsrv.CanonicalURIs = &falseBool

		case "pass_thru":
			if d.NextArg() {
				return d.ArgErr()
			}
			fsrv.PassThru = true

		case "etag_file_extensions":
			etagFileExtensions := d.RemainingArgs()
			if len(etagFileExtensions) == 0 {
				return d.ArgErr()
			}
			fsrv.EtagFileExtensions = etagFileExtensions

		default:
			return d.Errf("unknown subdirective '%s'", d.Val())
		}
	}

	return nil
}

// FinalizeUnmarshalCaddyfile finalizes the Caddyfile parsing which
// requires having an httpcaddyfile.Helper to function, to setup hidden Caddyfiles.
func (fsrv *FileServer) FinalizeUnmarshalCaddyfile(h httpcaddyfile.Helper) error {
	// Hide the Caddyfile (and any imported Caddyfiles).
	// This needs to be done in here instead of UnmarshalCaddyfile
	// because UnmarshalCaddyfile only has access to the dispenser
	// and not the helper, and only the helper has access to the
	// Caddyfiles function.
	if configFiles := h.Caddyfiles(); len(configFiles) > 0 {
		for _, file := range configFiles {
			file = filepath.Clean(file)
			if !fileHidden(file, fsrv.Hide) {
				// if there's no path separator, the file server module will hide all
				// files by that name, rather than a specific one; but we want to hide
				// only this specific file, so ensure there's always a path separator
				if !strings.Contains(file, separator) {
					file = "." + separator + file
				}
				fsrv.Hide = append(fsrv.Hide, file)
			}
		}
	}
	return nil
}

// parseTryFiles parses the try_files directive. It combines a file matcher
// with a rewrite directive, so this is not a standard handler directive.
// A try_files directive has this syntax (notice no matcher tokens accepted):
//
//	try_files <files...> {
//		policy first_exist|smallest_size|largest_size|most_recently_modified
//	}
//
// and is basically shorthand for:
//
//	@try_files file {
//		try_files <files...>
//		policy first_exist|smallest_size|largest_size|most_recently_modified
//	}
//	rewrite @try_files {http.matchers.file.relative}
//
// This directive rewrites request paths only, preserving any other part
// of the URI, unless the part is explicitly given in the file list. For
// example, if any of the files in the list have a query string:
//
//	try_files {path} index.php?{query}&p={path}
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

	// parse out the optional try policy
	var tryPolicy string
	for h.NextBlock(0) {
		switch h.Val() {
		case "policy":
			if tryPolicy != "" {
				return nil, h.Err("try policy already configured")
			}
			if !h.NextArg() {
				return nil, h.ArgErr()
			}
			tryPolicy = h.Val()

			switch tryPolicy {
			case tryPolicyFirstExist, tryPolicyFirstExistFallback, tryPolicyLargestSize, tryPolicySmallestSize, tryPolicyMostRecentlyMod:
			default:
				return nil, h.Errf("unrecognized try policy: %s", tryPolicy)
			}
		}
	}

	// makeRoute returns a route that tries the files listed in try
	// and then rewrites to the matched file; userQueryString is
	// appended to the rewrite rule.
	makeRoute := func(try []string, userQueryString string) []httpcaddyfile.ConfigValue {
		handler := rewrite.Rewrite{
			URI: "{http.matchers.file.relative}" + userQueryString,
		}
		matcherSet := caddy.ModuleMap{
			"file": h.JSON(MatchFile{TryFiles: try, TryPolicy: tryPolicy}),
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

var _ caddyfile.Unmarshaler = (*FileServer)(nil)
