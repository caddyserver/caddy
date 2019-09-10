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
	"encoding/json"

	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/rewrite"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("file_server", parseCaddyfile)
	httpcaddyfile.RegisterDirective("try_files", parseTryFiles)
}

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

		for h.NextBlock() {
			switch h.Val() {
			case "hide":
				fsrv.Hide = h.RemainingArgs()
				if len(fsrv.Hide) == 0 {
					return nil, h.ArgErr()
				}
			case "index":
				fsrv.IndexNames = h.RemainingArgs()
				if len(fsrv.Hide) == 0 {
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

func parseTryFiles(h httpcaddyfile.Helper) ([]httpcaddyfile.ConfigValue, error) {
	if !h.Next() {
		return nil, h.ArgErr()
	}

	try := h.RemainingArgs()
	if len(try) == 0 {
		return nil, h.ArgErr()
	}

	handler := rewrite.Rewrite{
		URI: "{http.matchers.file.relative}{http.request.uri.query_string}",
	}

	matcherSet := map[string]json.RawMessage{
		"file": h.JSON(MatchFile{
			TryFiles: try,
		}, nil),
	}

	return h.NewRoute(matcherSet, handler), nil
}
