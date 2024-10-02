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
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/headers"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

func init() {
	caddycmd.RegisterCommand(caddycmd.Command{
		Name:  "reverse-proxy",
		Usage: `[--from <addr>] [--to <addr>] [--change-host-header] [--insecure] [--internal-certs] [--disable-redirects] [--header-up "Field: value"] [--header-down "Field: value"] [--access-log] [--debug]`,
		Short: "A quick and production-ready reverse proxy",
		Long: `
A simple but production-ready reverse proxy. Useful for quick deployments,
demos, and development.

Simply shuttles HTTP(S) traffic from the --from address to the --to address.
Multiple --to addresses may be specified by repeating the flag.

Unless otherwise specified in the addresses, the --from address will be
assumed to be HTTPS if a hostname is given, and the --to address will be
assumed to be HTTP.

If the --from address has a host or IP, Caddy will attempt to serve the
proxy over HTTPS with a certificate (unless overridden by the HTTP scheme
or port).

If serving HTTPS: 
  --disable-redirects can be used to avoid binding to the HTTP port.
  --internal-certs can be used to force issuance certs using the internal
    CA instead of attempting to issue a public certificate.

For proxying:
  --header-up can be used to set a request header to send to the upstream.
  --header-down can be used to set a response header to send back to the client.
  --change-host-header sets the Host header on the request to the address
    of the upstream, instead of defaulting to the incoming Host header.
	This is a shortcut for --header-up "Host: {http.reverse_proxy.upstream.hostport}".
  --insecure disables TLS verification with the upstream. WARNING: THIS
    DISABLES SECURITY BY NOT VERIFYING THE UPSTREAM'S CERTIFICATE.
`,
		CobraFunc: func(cmd *cobra.Command) {
			cmd.Flags().StringP("from", "f", "localhost", "Address on which to receive traffic")
			cmd.Flags().StringSliceP("to", "t", []string{}, "Upstream address(es) to which traffic should be sent")
			cmd.Flags().BoolP("change-host-header", "c", false, "Set upstream Host header to address of upstream")
			cmd.Flags().BoolP("insecure", "", false, "Disable TLS verification (WARNING: DISABLES SECURITY BY NOT VERIFYING TLS CERTIFICATES!)")
			cmd.Flags().BoolP("disable-redirects", "r", false, "Disable HTTP->HTTPS redirects")
			cmd.Flags().BoolP("internal-certs", "i", false, "Use internal CA for issuing certs")
			cmd.Flags().StringSliceP("header-up", "H", []string{}, "Set a request header to send to the upstream (format: \"Field: value\")")
			cmd.Flags().StringSliceP("header-down", "d", []string{}, "Set a response header to send back to the client (format: \"Field: value\")")
			cmd.Flags().BoolP("access-log", "", false, "Enable the access log")
			cmd.Flags().BoolP("debug", "v", false, "Enable verbose debug logs")
			cmd.RunE = caddycmd.WrapCommandFuncForCobra(cmdReverseProxy)
		},
	})
}

func cmdReverseProxy(fs caddycmd.Flags) (int, error) {
	caddy.TrapSignals()

	from := fs.String("from")
	changeHost := fs.Bool("change-host-header")
	insecure := fs.Bool("insecure")
	disableRedir := fs.Bool("disable-redirects")
	internalCerts := fs.Bool("internal-certs")
	accessLog := fs.Bool("access-log")
	debug := fs.Bool("debug")

	httpPort := strconv.Itoa(caddyhttp.DefaultHTTPPort)
	httpsPort := strconv.Itoa(caddyhttp.DefaultHTTPSPort)

	to, err := fs.GetStringSlice("to")
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("invalid to flag: %v", err)
	}
	if len(to) == 0 {
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
	// mixing schemes isn't supported, so use first defined (if available)
	toAddresses := make([]string, len(to))
	var toScheme string
	for i, toLoc := range to {
		addr, err := parseUpstreamDialAddress(toLoc)
		if err != nil {
			return caddy.ExitCodeFailedStartup, fmt.Errorf("invalid upstream address %s: %v", toLoc, err)
		}
		if addr.scheme != "" && toScheme == "" {
			toScheme = addr.scheme
		}
		toAddresses[i] = addr.dialAddr()
	}

	// proceed to build the handler and server
	ht := HTTPTransport{}
	if toScheme == "https" {
		ht.TLS = new(TLSConfig)
		if insecure {
			ht.TLS.InsecureSkipVerify = true
		}
	}

	upstreamPool := UpstreamPool{}
	for _, toAddr := range toAddresses {
		parsedAddr, err := caddy.ParseNetworkAddress(toAddr)
		if err != nil {
			return caddy.ExitCodeFailedStartup, fmt.Errorf("invalid upstream address %s: %v", toAddr, err)
		}

		if parsedAddr.StartPort == 0 && parsedAddr.EndPort == 0 {
			// unix networks don't have ports
			upstreamPool = append(upstreamPool, &Upstream{
				Dial: toAddr,
			})
		} else {
			// expand a port range into multiple upstreams
			for i := parsedAddr.StartPort; i <= parsedAddr.EndPort; i++ {
				upstreamPool = append(upstreamPool, &Upstream{
					Dial: caddy.JoinNetworkAddress("", parsedAddr.Host, fmt.Sprint(i)),
				})
			}
		}
	}

	handler := Handler{
		TransportRaw: caddyconfig.JSONModuleObject(ht, "protocol", "http", nil),
		Upstreams:    upstreamPool,
	}

	// set up header_up
	headerUp, err := fs.GetStringSlice("header-up")
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("invalid header flag: %v", err)
	}
	if len(headerUp) > 0 {
		reqHdr := make(http.Header)
		for i, h := range headerUp {
			key, val, found := strings.Cut(h, ":")
			key, val = strings.TrimSpace(key), strings.TrimSpace(val)
			if !found || key == "" || val == "" {
				return caddy.ExitCodeFailedStartup, fmt.Errorf("header-up %d: invalid format \"%s\" (expecting \"Field: value\")", i, h)
			}
			reqHdr.Set(key, val)
		}
		handler.Headers = &headers.Handler{
			Request: &headers.HeaderOps{
				Set: reqHdr,
			},
		}
	}

	// set up header_down
	headerDown, err := fs.GetStringSlice("header-down")
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("invalid header flag: %v", err)
	}
	if len(headerDown) > 0 {
		respHdr := make(http.Header)
		for i, h := range headerDown {
			key, val, found := strings.Cut(h, ":")
			key, val = strings.TrimSpace(key), strings.TrimSpace(val)
			if !found || key == "" || val == "" {
				return caddy.ExitCodeFailedStartup, fmt.Errorf("header-down %d: invalid format \"%s\" (expecting \"Field: value\")", i, h)
			}
			respHdr.Set(key, val)
		}
		if handler.Headers == nil {
			handler.Headers = &headers.Handler{}
		}
		handler.Headers.Response = &headers.RespHeaderOps{
			HeaderOps: &headers.HeaderOps{
				Set: respHdr,
			},
		}
	}

	if changeHost {
		if handler.Headers == nil {
			handler.Headers = new(headers.Handler)
		}
		if handler.Headers.Request == nil {
			handler.Headers.Request = new(headers.HeaderOps)
		}
		if handler.Headers.Request.Set == nil {
			handler.Headers.Request.Set = http.Header{}
		}
		handler.Headers.Request.Set.Set("Host", "{http.reverse_proxy.upstream.hostport}")
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
	if accessLog {
		server.Logs = &caddyhttp.ServerLogConfig{}
	}

	if fromAddr.Scheme == "http" {
		server.AutoHTTPS = &caddyhttp.AutoHTTPSConfig{Disabled: true}
	} else if disableRedir {
		server.AutoHTTPS = &caddyhttp.AutoHTTPSConfig{DisableRedir: true}
	}

	httpApp := caddyhttp.App{
		Servers: map[string]*caddyhttp.Server{"proxy": server},
	}

	appsRaw := caddy.ModuleMap{
		"http": caddyconfig.JSON(httpApp, nil),
	}
	if internalCerts && fromAddr.Host != "" {
		tlsApp := caddytls.TLS{
			Automation: &caddytls.AutomationConfig{
				Policies: []*caddytls.AutomationPolicy{{
					SubjectsRaw: []string{fromAddr.Host},
					IssuersRaw:  []json.RawMessage{json.RawMessage(`{"module":"internal"}`)},
				}},
			},
		}
		appsRaw["tls"] = caddyconfig.JSON(tlsApp, nil)
	}

	var false bool
	cfg := &caddy.Config{
		Admin: &caddy.AdminConfig{
			Disabled: true,
			Config: &caddy.ConfigSettings{
				Persist: &false,
			},
		},
		AppsRaw: appsRaw,
	}

	if debug {
		cfg.Logging = &caddy.Logging{
			Logs: map[string]*caddy.CustomLog{
				"default": {BaseLog: caddy.BaseLog{Level: zap.DebugLevel.CapitalString()}},
			},
		}
	}

	err = caddy.Run(cfg)
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}

	caddy.Log().Info("caddy proxying", zap.String("from", fromAddr.String()), zap.Strings("to", toAddresses))
	if len(toAddresses) > 1 {
		caddy.Log().Info("using default load balancing policy", zap.String("policy", "random"))
	}

	select {}
}
