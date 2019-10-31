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
	"net/http"
	"net/url"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/headers"
	"github.com/mholt/certmagic"
)

func init() {
	caddycmd.RegisterCommand(caddycmd.Command{
		Name:  "reverse-proxy",
		Func:  cmdReverseProxy,
		Usage: "[--from <addr>] [--to <addr>]",
		Short: "A quick and production-ready reverse proxy",
		Long: `
A simple but production-ready reverse proxy. Useful for quick deployments,
demos, and development.

Simply shuttles HTTP traffic from the --from address to the --to address.

If the --from address has a domain name, Caddy will attempt to serve the
proxy over HTTPS with a certificate.
`,
		Flags: func() *flag.FlagSet {
			fs := flag.NewFlagSet("file-server", flag.ExitOnError)
			fs.String("from", "", "Address to receive traffic on")
			fs.String("to", "", "Upstream address to proxy traffic to")
			return fs
		}(),
	})
}

func cmdReverseProxy(fs caddycmd.Flags) (int, error) {
	from := fs.String("from")
	to := fs.String("to")

	if from == "" {
		from = "localhost:" + httpcaddyfile.DefaultPort
	}

	// URLs need a scheme in order to parse successfully
	if !strings.Contains(from, "://") {
		from = "http://" + from
	}
	if !strings.Contains(to, "://") {
		to = "http://" + to
	}

	fromURL, err := url.Parse(from)
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("parsing 'from' URL: %v", err)
	}
	toURL, err := url.Parse(to)
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("parsing 'to' URL: %v", err)
	}

	ht := HTTPTransport{}
	if toURL.Scheme == "https" {
		ht.TLS = new(TLSConfig)
	}

	handler := Handler{
		TransportRaw: caddyconfig.JSONModuleObject(ht, "protocol", "http", nil),
		Upstreams:    UpstreamPool{{Dial: toURL.Host}},
		Headers: &headers.Handler{
			Request: &headers.HeaderOps{
				Set: http.Header{
					"Host": []string{"{http.handlers.reverse_proxy.upstream.host}"},
				},
			},
		},
	}

	route := caddyhttp.Route{
		HandlersRaw: []json.RawMessage{
			caddyconfig.JSONModuleObject(handler, "handler", "reverse_proxy", nil),
		},
	}
	urlHost := fromURL.Hostname()
	if urlHost != "" {
		route.MatcherSetsRaw = []map[string]json.RawMessage{
			map[string]json.RawMessage{
				"host": caddyconfig.JSON(caddyhttp.MatchHost{urlHost}, nil),
			},
		}
	}

	listen := ":80"
	if urlPort := fromURL.Port(); urlPort != "" {
		listen = ":" + urlPort
	} else if certmagic.HostQualifies(urlHost) {
		listen = ":443"
	}

	server := &caddyhttp.Server{
		Routes: caddyhttp.RouteList{route},
		Listen: []string{listen},
	}

	httpApp := caddyhttp.App{
		Servers: map[string]*caddyhttp.Server{"proxy": server},
	}

	cfg := &caddy.Config{
		AppsRaw: map[string]json.RawMessage{
			"http": caddyconfig.JSON(httpApp, nil),
		},
	}

	err = caddy.Run(cfg)
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}

	fmt.Printf("Caddy 2 proxying from %s to %s\n", fromURL, toURL)

	select {}
}
