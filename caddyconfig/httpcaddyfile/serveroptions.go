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

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/dustin/go-humanize"
)

// serverOptions collects server config overrides parsed from Caddyfile global options
type serverOptions struct {
	// If set, will only apply these options to servers that contain a
	// listener address that matches exactly. If empty, will apply to all
	// servers that were not already matched by another serverOptions.
	ListenerAddress string

	// These will all map 1:1 to the caddyhttp.Server struct
	ListenerWrappersRaw  []json.RawMessage
	ReadTimeout          caddy.Duration
	ReadHeaderTimeout    caddy.Duration
	WriteTimeout         caddy.Duration
	IdleTimeout          caddy.Duration
	KeepAliveInterval    caddy.Duration
	MaxHeaderBytes       int
	Protocols            []string
	StrictSNIHost        *bool
	ShouldLogCredentials bool
}

func unmarshalCaddyfileServerOptions(d *caddyfile.Dispenser) (any, error) {
	serverOpts := serverOptions{}
	for d.Next() {
		if d.NextArg() {
			serverOpts.ListenerAddress = d.Val()
			if d.NextArg() {
				return nil, d.ArgErr()
			}
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
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
					if sliceContains(serverOpts.Protocols, proto) {
						return nil, d.Errf("protocol %s specified more than once", proto)
					}
					serverOpts.Protocols = append(serverOpts.Protocols, proto)
				}
				if d.NextBlock(0) {
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

			// TODO: DEPRECATED. (August 2022)
			case "protocol":
				caddy.Log().Named("caddyfile").Warn("DEPRECATED: protocol sub-option will be removed soon")

				for nesting := d.Nesting(); d.NextBlock(nesting); {
					switch d.Val() {
					case "allow_h2c":
						caddy.Log().Named("caddyfile").Warn("DEPRECATED: allow_h2c will be removed soon; use protocols option instead")

						if d.NextArg() {
							return nil, d.ArgErr()
						}
						if sliceContains(serverOpts.Protocols, "h2c") {
							return nil, d.Errf("protocol h2c already specified")
						}
						serverOpts.Protocols = append(serverOpts.Protocols, "h2c")

					case "strict_sni_host":
						caddy.Log().Named("caddyfile").Warn("DEPRECATED: protocol > strict_sni_host in this position will be removed soon; move up to the servers block instead")

						if d.NextArg() && d.Val() != "insecure_off" && d.Val() != "on" {
							return nil, d.Errf("strict_sni_host only supports 'on' or 'insecure_off', got '%s'", d.Val())
						}
						boolVal := true
						if d.Val() == "insecure_off" {
							boolVal = false
						}
						serverOpts.StrictSNIHost = &boolVal

					default:
						return nil, d.Errf("unrecognized protocol option '%s'", d.Val())
					}
				}

			default:
				return nil, d.Errf("unrecognized servers option '%s'", d.Val())
			}
		}
	}
	return serverOpts, nil
}

// applyServerOptions sets the server options on the appropriate servers
func applyServerOptions(
	servers map[string]*caddyhttp.Server,
	options map[string]any,
	warnings *[]caddyconfig.Warning,
) error {
	serverOpts, ok := options["servers"].([]serverOptions)
	if !ok {
		return nil
	}

	for _, server := range servers {
		// find the options that apply to this server
		opts := func() *serverOptions {
			for _, entry := range serverOpts {
				if entry.ListenerAddress == "" {
					return &entry
				}
				for _, listener := range server.Listen {
					if entry.ListenerAddress == listener {
						return &entry
					}
				}
			}
			return nil
		}()

		// if none apply, then move to the next server
		if opts == nil {
			continue
		}

		// set all the options
		server.ListenerWrappersRaw = opts.ListenerWrappersRaw
		server.ReadTimeout = opts.ReadTimeout
		server.ReadHeaderTimeout = opts.ReadHeaderTimeout
		server.WriteTimeout = opts.WriteTimeout
		server.IdleTimeout = opts.IdleTimeout
		server.KeepAliveInterval = opts.KeepAliveInterval
		server.MaxHeaderBytes = opts.MaxHeaderBytes
		server.Protocols = opts.Protocols
		server.StrictSNIHost = opts.StrictSNIHost
		if opts.ShouldLogCredentials {
			if server.Logs == nil {
				server.Logs = &caddyhttp.ServerLogConfig{}
			}
			server.Logs.ShouldLogCredentials = opts.ShouldLogCredentials
		}
	}

	return nil
}
