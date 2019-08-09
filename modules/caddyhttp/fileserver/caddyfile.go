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
	"github.com/caddyserver/caddy/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/caddyconfig/httpcaddyfile"
)

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens. Syntax:
//
//     file_server [<matcher>] [browse] {
//         hide <files...>
//         index <files...>
//         browse [<template_file>]
//         root <path>
//     }
//
// If browse is given on the first line, it can't be used in the block also.
// The default root is the one given by the root directive.
func (fsrv *FileServer) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
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

		for d.NextBlock() {
			switch d.Val() {
			case "hide":
				fsrv.Hide = d.RemainingArgs()
				if len(fsrv.Hide) == 0 {
					return d.ArgErr()
				}
			case "index":
				fsrv.IndexNames = d.RemainingArgs()
				if len(fsrv.Hide) == 0 {
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
			default:
				return d.Errf("unknown subdirective '%s'", d.Val())
			}
		}
	}

	// if no root was configured explicitly, use site root
	if fsrv.Root == "" {
		fsrv.Root = "{http.var.root}"
	}

	return nil
}

// Bucket returns the HTTP Caddyfile handler bucket number.
func (fsrv FileServer) Bucket() int { return 7 }

// Interface guard
var _ httpcaddyfile.HandlerDirective = (*FileServer)(nil)
