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
	"io"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	caddytpl "github.com/caddyserver/caddy/v2/modules/caddyhttp/templates"
)

func init() {
	caddycmd.RegisterCommand(caddycmd.Command{
		Name:  "file-server",
		Usage: "[--domain <example.com>] [--root <path>] [--listen <addr>] [--browse] [--access-log]",
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
		CobraFunc: func(cmd *cobra.Command) {
			cmd.Flags().StringP("domain", "d", "", "Domain name at which to serve the files")
			cmd.Flags().StringP("root", "r", "", "The path to the root of the site")
			cmd.Flags().StringP("listen", "l", "", "The address to which to bind the listener")
			cmd.Flags().BoolP("browse", "b", false, "Enable directory browsing")
			cmd.Flags().BoolP("templates", "t", false, "Enable template rendering")
			cmd.Flags().BoolP("access-log", "a", false, "Enable the access log")
			cmd.Flags().BoolP("debug", "v", false, "Enable verbose debug logs")
			cmd.RunE = caddycmd.WrapCommandFuncForCobra(cmdFileServer)
			cmd.AddCommand(&cobra.Command{
				Use:     "export-template",
				Short:   "Exports the default file browser template",
				Example: "caddy file-server export-template > browse.html",
				RunE: func(cmd *cobra.Command, args []string) error {
					_, err := io.WriteString(os.Stdout, BrowseTemplate)
					return err
				},
			})
		},
	})
}

func cmdFileServer(fs caddycmd.Flags) (int, error) {
	caddy.TrapSignals()

	domain := fs.String("domain")
	root := fs.String("root")
	listen := fs.String("listen")
	browse := fs.Bool("browse")
	templates := fs.Bool("templates")
	accessLog := fs.Bool("access-log")
	debug := fs.Bool("debug")

	var handlers []json.RawMessage

	if templates {
		handler := caddytpl.Templates{FileRoot: root}
		handlers = append(handlers, caddyconfig.JSONModuleObject(handler, "handler", "templates", nil))
	}

	handler := FileServer{Root: root}
	if browse {
		handler.Browse = new(Browse)
	}

	handlers = append(handlers, caddyconfig.JSONModuleObject(handler, "handler", "file_server", nil))

	route := caddyhttp.Route{HandlersRaw: handlers}

	if domain != "" {
		route.MatcherSetsRaw = []caddy.ModuleMap{
			{
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
	if accessLog {
		server.Logs = &caddyhttp.ServerLogConfig{}
	}

	httpApp := caddyhttp.App{
		Servers: map[string]*caddyhttp.Server{"static": server},
	}

	var false bool
	cfg := &caddy.Config{
		Admin: &caddy.AdminConfig{
			Disabled: true,
			Config: &caddy.ConfigSettings{
				Persist: &false,
			},
		},
		AppsRaw: caddy.ModuleMap{
			"http": caddyconfig.JSON(httpApp, nil),
		},
	}

	if debug {
		cfg.Logging = &caddy.Logging{
			Logs: map[string]*caddy.CustomLog{
				"default": {
					BaseLog: caddy.BaseLog{Level: zap.DebugLevel.CapitalString()},
				},
			},
		}
	}

	err := caddy.Run(cfg)
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}

	log.Printf("Caddy serving static files on %s", listen)

	select {}
}
