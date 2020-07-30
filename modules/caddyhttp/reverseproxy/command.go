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

package reverseproxy

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/headers"
)

func init() {
	caddycmd.RegisterCommand(caddycmd.Command{
		Name:  "reverse-proxy",
		Func:  cmdReverseProxy,
		Usage: "[--from <addr>] [--to <addr>] [--change-host-header]",
		Short: "A quick and production-ready reverse proxy",
		Long: `
A simple but production-ready reverse proxy. Useful for quick deployments,
demos, and development.

Simply shuttles HTTP(S) traffic from the --from address to the --to address.

Unless otherwise specified in the addresses, the --from address will be
assumed to be HTTPS if a hostname is given, and the --to address will be
assumed to be HTTP.

If the --from address has a host or IP, Caddy will attempt to serve the
proxy over HTTPS with a certificate (unless overridden by the HTTP scheme
or port).

If --change-host-header is set, the Host header on the request will be modified
from its original incoming value to the address of the upstream. (Otherwise, by
default, all incoming headers are passed through unmodified.)
`,
		Flags: func() *flag.FlagSet {
			fs := flag.NewFlagSet("reverse-proxy", flag.ExitOnError)
			fs.String("from", "localhost", "Address on which to receive traffic")
			fs.String("to", "", "Upstream address to which to to proxy traffic")
			fs.Bool("change-host-header", false, "Set upstream Host header to address of upstream")
			fs.Bool("insecure", false, "Disable TLS verification (WARNING: DISABLES SECURITY, WHY ARE YOU EVEN USING TLS?)")
			return fs
		}(),
	})
}

func cmdReverseProxy(fs caddycmd.Flags) (int, error) {
	caddy.TrapSignals()

	from := fs.String("from")
	to := fs.String("to")
	changeHost := fs.Bool("change-host-header")
	insecure := fs.Bool("insecure")

	httpPort := strconv.Itoa(caddyhttp.DefaultHTTPPort)
	httpsPort := strconv.Itoa(caddyhttp.DefaultHTTPSPort)

	if to == "" {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("--to is required")
	}

	// set up the downstream address; assume missing information from given parts
	fromAddr, err := httpcaddyfile.ParseAddress(from)
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("invalid downstream address %s: %v", from, err)
	}
	if fromAddr.Path != "" {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("paths are not allowed: %s", from)
	}
	if fromAddr.Scheme == "" {
		if fromAddr.Port == httpPort || fromAddr.Host == "" {
			fromAddr.Scheme = "http"
		} else {
			fromAddr.Scheme = "https"
		}
	}
	if fromAddr.Port == "" {
		if fromAddr.Scheme == "http" {
			fromAddr.Port = httpPort
		} else if fromAddr.Scheme == "https" {
			fromAddr.Port = httpsPort
		}
	}

	// set up the upstream address; assume missing information from given parts
	toAddr, err := httpcaddyfile.ParseAddress(to)
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("invalid upstream address %s: %v", to, err)
	}
	if toAddr.Path != "" {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("paths are not allowed: %s", to)
	}
	if toAddr.Scheme == "" {
		if toAddr.Port == httpsPort {
			toAddr.Scheme = "https"
		} else {
			toAddr.Scheme = "http"
		}
	}
	if toAddr.Port == "" {
		if toAddr.Scheme == "http" {
			toAddr.Port = httpPort
		} else if toAddr.Scheme == "https" {
			toAddr.Port = httpsPort
		}
	}

	// proceed to build the handler and server

	ht := HTTPTransport{}
	if toAddr.Scheme == "https" {
		ht.TLS = new(TLSConfig)
		if insecure {
			ht.TLS.InsecureSkipVerify = true
		}
	}

	handler := Handler{
		TransportRaw: caddyconfig.JSONModuleObject(ht, "protocol", "http", nil),
		Upstreams:    UpstreamPool{{Dial: net.JoinHostPort(toAddr.Host, toAddr.Port)}},
	}

	if changeHost {
		handler.Headers = &headers.Handler{
			Request: &headers.HeaderOps{
				Set: http.Header{
					"Host": []string{"{http.reverse_proxy.upstream.hostport}"},
				},
			},
		}
	}

	route := caddyhttp.Route{
		HandlersRaw: []json.RawMessage{
			caddyconfig.JSONModuleObject(handler, "handler", "reverse_proxy", nil),
		},
	}
	if fromAddr.Host != "" {
		route.MatcherSetsRaw = []caddy.ModuleMap{
			{
				"host": caddyconfig.JSON(caddyhttp.MatchHost{fromAddr.Host}, nil),
			},
		}
	}

	server := &caddyhttp.Server{
		Routes: caddyhttp.RouteList{route},
		Listen: []string{":" + fromAddr.Port},
	}

	httpApp := caddyhttp.App{
		Servers: map[string]*caddyhttp.Server{"proxy": server},
	}

	cfg := &caddy.Config{
		Admin: &caddy.AdminConfig{Disabled: true},
		AppsRaw: caddy.ModuleMap{
			"http": caddyconfig.JSON(httpApp, nil),
		},
	}

	err = caddy.Run(cfg)
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}

	fmt.Printf("Caddy proxying %s -> %s\n", fromAddr.String(), toAddr.String())

	select {}
}
