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
	"flag"
	"log"
	"strconv"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/certmagic"
)

func init() {
	caddycmd.RegisterCommand(caddycmd.Command{
		Name:  "file-server",
		Func:  cmdFileServer,
		Usage: "[--domain <example.com>] [--root <path>] [--listen <addr>] [--browse]",
		Short: "Spins up a production-ready file server",
		Long: `
A simple but production-ready file server. Useful for quick deployments,
demos, and development.

The listener's socket address can be customized with the --listen flag.

If a domain name is specified with --domain, the default listener address
will be changed to the HTTPS port and the server will use HTTPS. If using
a public domain, ensure A/AAAA records are properly configured before
using this option.

If --browse is enabled, requests for folders without an index file will
respond with a file listing.`,
		Flags: func() *flag.FlagSet {
			fs := flag.NewFlagSet("file-server", flag.ExitOnError)
			fs.String("domain", "", "Domain name at which to serve the files")
			fs.String("root", "", "The path to the root of the site")
			fs.String("listen", "", "The address to which to bind the listener")
			fs.Bool("browse", false, "Whether to enable directory browsing")
			return fs
		}(),
	})
}

func cmdFileServer(fs caddycmd.Flags) (int, error) {
	domain := fs.String("domain")
	root := fs.String("root")
	listen := fs.String("listen")
	browse := fs.Bool("browse")

	handler := FileServer{Root: root}
	if browse {
		handler.Browse = new(Browse)
	}

	route := caddyhttp.Route{
		HandlersRaw: []json.RawMessage{
			caddyconfig.JSONModuleObject(handler, "handler", "file_server", nil),
		},
	}
	if domain != "" {
		route.MatcherSetsRaw = []caddy.ModuleMap{
			caddy.ModuleMap{
				"host": caddyconfig.JSON(caddyhttp.MatchHost{domain}, nil),
			},
		}
	}

	server := &caddyhttp.Server{
		ReadHeaderTimeout: caddy.Duration(10 * time.Second),
		IdleTimeout:       caddy.Duration(30 * time.Second),
		MaxHeaderBytes:    1024 * 10,
		Routes:            caddyhttp.RouteList{route},
	}
	if listen == "" {
		if domain == "" {
			listen = ":80"
		} else {
			listen = ":" + strconv.Itoa(certmagic.HTTPSPort)
		}
	}
	server.Listen = []string{listen}

	httpApp := caddyhttp.App{
		Servers: map[string]*caddyhttp.Server{"static": server},
	}

	cfg := &caddy.Config{
		Admin: &caddy.AdminConfig{Disabled: true},
		AppsRaw: caddy.ModuleMap{
			"http": caddyconfig.JSON(httpApp, nil),
		},
	}

	err := caddy.Run(cfg)
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}

	log.Printf("Caddy 2 serving static files on %s", listen)

	select {}
}
