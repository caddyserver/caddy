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

package httpcaddyfile

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/dustin/go-humanize"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// serverOptions collects server config overrides parsed from Caddyfile global options
type serverOptions struct {
	// If set, will only apply these options to servers that contain a
	// listener address that matches exactly. If empty, will apply to all
	// servers that were not already matched by another serverOptions.
	ListenerAddress string

	// These will all map 1:1 to the caddyhttp.Server struct
	Name                 string
	ListenerWrappersRaw  []json.RawMessage
	ReadTimeout          caddy.Duration
	ReadHeaderTimeout    caddy.Duration
	WriteTimeout         caddy.Duration
	IdleTimeout          caddy.Duration
	KeepAliveInterval    caddy.Duration
	MaxHeaderBytes       int
	EnableFullDuplex     bool
	Protocols            []string
	StrictSNIHost        *bool
	TrustedProxiesRaw    json.RawMessage
	TrustedProxiesStrict int
	ClientIPHeaders      []string
	ShouldLogCredentials bool
	Metrics              *caddyhttp.Metrics
	Trace                bool // TODO: EXPERIMENTAL
}

func unmarshalCaddyfileServerOptions(d *caddyfile.Dispenser) (any, error) {
	d.Next() // consume option name

	serverOpts := serverOptions{}
	if d.NextArg() {
		serverOpts.ListenerAddress = d.Val()
		if d.NextArg() {
			return nil, d.ArgErr()
		}
	}
	for d.NextBlock(0) {
		switch d.Val() {
		case "name":
			if serverOpts.ListenerAddress == "" {
				return nil, d.Errf("cannot set a name for a server without a listener address")
			}
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			serverOpts.Name = d.Val()

		case "listener_wrappers":
			for nesting := d.Nesting(); d.NextBlock(nesting); {
				modID := "caddy.listeners." + d.Val()
				unm, err := caddyfile.UnmarshalModule(d, modID)
				if err != nil {
					return nil, err
				}
				listenerWrapper, ok := unm.(caddy.ListenerWrapper)
				if !ok {
					return nil, fmt.Errorf("module %s (%T) is not a listener wrapper", modID, unm)
				}
				jsonListenerWrapper := caddyconfig.JSONModuleObject(
					listenerWrapper,
					"wrapper",
					listenerWrapper.(caddy.Module).CaddyModule().ID.Name(),
					nil,
				)
				serverOpts.ListenerWrappersRaw = append(serverOpts.ListenerWrappersRaw, jsonListenerWrapper)
			}

		case "timeouts":
			for nesting := d.Nesting(); d.NextBlock(nesting); {
				switch d.Val() {
				case "read_body":
					if !d.NextArg() {
						return nil, d.ArgErr()
					}
					dur, err := caddy.ParseDuration(d.Val())
					if err != nil {
						return nil, d.Errf("parsing read_body timeout duration: %v", err)
					}
					serverOpts.ReadTimeout = caddy.Duration(dur)

				case "read_header":
					if !d.NextArg() {
						return nil, d.ArgErr()
					}
					dur, err := caddy.ParseDuration(d.Val())
					if err != nil {
						return nil, d.Errf("parsing read_header timeout duration: %v", err)
					}
					serverOpts.ReadHeaderTimeout = caddy.Duration(dur)

				case "write":
					if !d.NextArg() {
						return nil, d.ArgErr()
					}
					dur, err := caddy.ParseDuration(d.Val())
					if err != nil {
						return nil, d.Errf("parsing write timeout duration: %v", err)
					}
					serverOpts.WriteTimeout = caddy.Duration(dur)

				case "idle":
					if !d.NextArg() {
						return nil, d.ArgErr()
					}
					dur, err := caddy.ParseDuration(d.Val())
					if err != nil {
						return nil, d.Errf("parsing idle timeout duration: %v", err)
					}
					serverOpts.IdleTimeout = caddy.Duration(dur)

				default:
					return nil, d.Errf("unrecognized timeouts option '%s'", d.Val())
				}
			}
		case "keepalive_interval":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return nil, d.Errf("parsing keepalive interval duration: %v", err)
			}
			serverOpts.KeepAliveInterval = caddy.Duration(dur)

		case "max_header_size":
			var sizeStr string
			if !d.AllArgs(&sizeStr) {
				return nil, d.ArgErr()
			}
			size, err := humanize.ParseBytes(sizeStr)
			if err != nil {
				return nil, d.Errf("parsing max_header_size: %v", err)
			}
			serverOpts.MaxHeaderBytes = int(size)

		case "enable_full_duplex":
			if d.NextArg() {
				return nil, d.ArgErr()
			}
			serverOpts.EnableFullDuplex = true

		case "log_credentials":
			if d.NextArg() {
				return nil, d.ArgErr()
			}
			serverOpts.ShouldLogCredentials = true

		case "protocols":
			protos := d.RemainingArgs()
			for _, proto := range protos {
				if proto != "h1" && proto != "h2" && proto != "h2c" && proto != "h3" {
					return nil, d.Errf("unknown protocol '%s': expected h1, h2, h2c, or h3", proto)
				}
				if slices.Contains(serverOpts.Protocols, proto) {
					return nil, d.Errf("protocol %s specified more than once", proto)
				}
				serverOpts.Protocols = append(serverOpts.Protocols, proto)
			}
			if nesting := d.Nesting(); d.NextBlock(nesting) {
				return nil, d.ArgErr()
			}

		case "strict_sni_host":
			if d.NextArg() && d.Val() != "insecure_off" && d.Val() != "on" {
				return nil, d.Errf("strict_sni_host only supports 'on' or 'insecure_off', got '%s'", d.Val())
			}
			boolVal := true
			if d.Val() == "insecure_off" {
				boolVal = false
			}
			serverOpts.StrictSNIHost = &boolVal

		case "trusted_proxies":
			if !d.NextArg() {
				return nil, d.Err("trusted_proxies expects an IP range source module name as its first argument")
			}
			modID := "http.ip_sources." + d.Val()
			unm, err := caddyfile.UnmarshalModule(d, modID)
			if err != nil {
				return nil, err
			}
			source, ok := unm.(caddyhttp.IPRangeSource)
			if !ok {
				return nil, fmt.Errorf("module %s (%T) is not an IP range source", modID, unm)
			}
			jsonSource := caddyconfig.JSONModuleObject(
				source,
				"source",
				source.(caddy.Module).CaddyModule().ID.Name(),
				nil,
			)
			serverOpts.TrustedProxiesRaw = jsonSource

		case "trusted_proxies_strict":
			if d.NextArg() {
				return nil, d.ArgErr()
			}
			serverOpts.TrustedProxiesStrict = 1

		case "client_ip_headers":
			headers := d.RemainingArgs()
			for _, header := range headers {
				if slices.Contains(serverOpts.ClientIPHeaders, header) {
					return nil, d.Errf("client IP header %s specified more than once", header)
				}
				serverOpts.ClientIPHeaders = append(serverOpts.ClientIPHeaders, header)
			}
			if nesting := d.Nesting(); d.NextBlock(nesting) {
				return nil, d.ArgErr()
			}

		case "metrics":
			caddy.Log().Warn("The nested 'metrics' option inside `servers` is deprecated and will be removed in the next major version. Use the global 'metrics' option instead.")
			serverOpts.Metrics = new(caddyhttp.Metrics)
			for nesting := d.Nesting(); d.NextBlock(nesting); {
				switch d.Val() {
				case "per_host":
					serverOpts.Metrics.PerHost = true
				}
			}

		case "trace":
			if d.NextArg() {
				return nil, d.ArgErr()
			}
			serverOpts.Trace = true

		default:
			return nil, d.Errf("unrecognized servers option '%s'", d.Val())
		}
	}
	return serverOpts, nil
}

// applyServerOptions sets the server options on the appropriate servers
func applyServerOptions(
	servers map[string]*caddyhttp.Server,
	options map[string]any,
	_ *[]caddyconfig.Warning,
) error {
	serverOpts, ok := options["servers"].([]serverOptions)
	if !ok {
		return nil
	}

	// check for duplicate names, which would clobber the config
	existingNames := map[string]bool{}
	for _, opts := range serverOpts {
		if opts.Name == "" {
			continue
		}
		if existingNames[opts.Name] {
			return fmt.Errorf("cannot use duplicate server name '%s'", opts.Name)
		}
		existingNames[opts.Name] = true
	}

	// collect the server name overrides
	nameReplacements := map[string]string{}

	for key, server := range servers {
		// find the options that apply to this server
		optsIndex := slices.IndexFunc(serverOpts, func(s serverOptions) bool {
			return s.ListenerAddress == "" || slices.Contains(server.Listen, s.ListenerAddress)
		})

		// if none apply, then move to the next server
		if optsIndex == -1 {
			continue
		}
		opts := serverOpts[optsIndex]

		// set all the options
		server.ListenerWrappersRaw = opts.ListenerWrappersRaw
		server.ReadTimeout = opts.ReadTimeout
		server.ReadHeaderTimeout = opts.ReadHeaderTimeout
		server.WriteTimeout = opts.WriteTimeout
		server.IdleTimeout = opts.IdleTimeout
		server.KeepAliveInterval = opts.KeepAliveInterval
		server.MaxHeaderBytes = opts.MaxHeaderBytes
		server.EnableFullDuplex = opts.EnableFullDuplex
		server.Protocols = opts.Protocols
		server.StrictSNIHost = opts.StrictSNIHost
		server.TrustedProxiesRaw = opts.TrustedProxiesRaw
		server.ClientIPHeaders = opts.ClientIPHeaders
		server.TrustedProxiesStrict = opts.TrustedProxiesStrict
		server.Metrics = opts.Metrics
		if opts.ShouldLogCredentials {
			if server.Logs == nil {
				server.Logs = new(caddyhttp.ServerLogConfig)
			}
			server.Logs.ShouldLogCredentials = opts.ShouldLogCredentials
		}
		if opts.Trace {
			// TODO: THIS IS EXPERIMENTAL (MAY 2024)
			if server.Logs == nil {
				server.Logs = new(caddyhttp.ServerLogConfig)
			}
			server.Logs.Trace = opts.Trace
		}

		if opts.Name != "" {
			nameReplacements[key] = opts.Name
		}
	}

	// rename the servers if marked to do so
	for old, new := range nameReplacements {
		servers[new] = servers[old]
		delete(servers, old)
	}

	return nil
}
