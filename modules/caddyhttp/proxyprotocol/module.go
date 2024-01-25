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

package proxyprotocol

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func init() {
	caddy.RegisterModule(ListenerWrapper{})
}

func (ListenerWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.proxy_protocol",
		New: func() caddy.Module { return new(ListenerWrapper) },
	}
}

// UnmarshalCaddyfile sets up the listener Listenerwrapper from Caddyfile tokens. Syntax:
//
//	proxy_protocol {
//		timeout <duration>
//		allow <IPs...>
//		deny <IPs...>
//		fallback_policy <policy>
//	}
func (w *ListenerWrapper) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume wrapper name

	// No same-line options are supported
	if d.NextArg() {
		return d.ArgErr()
	}

	for d.NextBlock(0) {
		switch d.Val() {
		case "timeout":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("parsing proxy_protocol timeout duration: %v", err)
			}
			w.Timeout = caddy.Duration(dur)

		case "allow":
			w.Allow = append(w.Allow, d.RemainingArgs()...)
		case "deny":
			w.Deny = append(w.Deny, d.RemainingArgs()...)
		case "fallback_policy":
			if !d.NextArg() {
				return d.ArgErr()
			}
			p, err := parsePolicy(d.Val())
			if err != nil {
				return d.WrapErr(err)
			}
			w.FallbackPolicy = p
		default:
			return d.ArgErr()
		}
	}
	return nil
}

// Interface guards
var (
	_ caddy.Provisioner     = (*ListenerWrapper)(nil)
	_ caddy.Module          = (*ListenerWrapper)(nil)
	_ caddy.ListenerWrapper = (*ListenerWrapper)(nil)
	_ caddyfile.Unmarshaler = (*ListenerWrapper)(nil)
)
