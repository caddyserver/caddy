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
	AllowH2C             bool
	ExperimentalHTTP3    bool
	StrictSNIHost        *bool
	ShouldLogCredentials bool
}

func unmarshalCaddyfileServerOptions(d *caddyfile.Dispenser) (interface{}, error) {
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

			case "protocol":
				for nesting := d.Nesting(); d.NextBlock(nesting); {
					switch d.Val() {
					case "allow_h2c":
						if d.NextArg() {
							return nil, d.ArgErr()
						}
						serverOpts.AllowH2C = true

					case "experimental_http3":
						if d.NextArg() {
							return nil, d.ArgErr()
						}
						serverOpts.ExperimentalHTTP3 = true

					case "strict_sni_host":
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
	options map[string]interface{},
	warnings *[]caddyconfig.Warning,
) error {
	// If experimental HTTP/3 is enabled, enable it on each server.
	// We already know there won't be a conflict with serverOptions because
	// we validated earlier that "experimental_http3" cannot be set at the same
	// time as "servers"
	if enableH3, ok := options["experimental_http3"].(bool); ok && enableH3 {
		*warnings = append(*warnings, caddyconfig.Warning{Message: "the 'experimental_http3' global option is deprecated, please use the 'servers > protocol > experimental_http3' option instead"})
		for _, srv := range servers {
			srv.ExperimentalHTTP3 = true
		}
	}

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
		server.AllowH2C = opts.AllowH2C
		server.ExperimentalHTTP3 = opts.ExperimentalHTTP3
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
