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
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/headers"
	"github.com/dustin/go-humanize"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("reverse_proxy", parseCaddyfile)
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	rp := new(Handler)
	err := rp.UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		return nil, err
	}
	return rp, nil
}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens. Syntax:
//
//     reverse_proxy [<matcher>] [<upstreams...>] {
//         # upstreams
//         to <upstreams...>
//
//         # load balancing
//         lb_policy <name> [<options...>]
//         lb_try_duration <duration>
//         lb_try_interval <interval>
//
//         # active health checking
//         health_path <path>
//         health_port <port>
//         health_interval <interval>
//         health_timeout <duration>
//         health_status <status>
//         health_body <regexp>
//
//         # passive health checking
//         max_fails <num>
//         fail_duration <duration>
//         max_conns <num>
//         unhealthy_status <status>
//         unhealthy_latency <duration>
//
//         # streaming
//         flush_interval <duration>
//
//         # header manipulation
//         header_up   [+|-]<field> [<value|regexp> [<replacement>]]
//         header_down [+|-]<field> [<value|regexp> [<replacement>]]
//
//         # round trip
//         transport <name> {
//             ...
//         }
//     }
//
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for _, up := range d.RemainingArgs() {
			h.Upstreams = append(h.Upstreams, &Upstream{Dial: up})
		}

		for d.NextBlock(0) {
			switch d.Val() {
			case "to":
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}
				for _, up := range args {
					h.Upstreams = append(h.Upstreams, &Upstream{Dial: up})
				}

			case "lb_policy":
				if !d.NextArg() {
					return d.ArgErr()
				}
				if h.LoadBalancing != nil && h.LoadBalancing.SelectionPolicyRaw != nil {
					return d.Err("load balancing selection policy already specified")
				}
				name := d.Val()
				mod, err := caddy.GetModule("http.reverse_proxy.selection_policies." + name)
				if err != nil {
					return d.Errf("getting load balancing policy module '%s': %v", mod, err)
				}
				unm, ok := mod.New().(caddyfile.Unmarshaler)
				if !ok {
					return d.Errf("load balancing policy module '%s' is not a Caddyfile unmarshaler", mod)
				}
				err = unm.UnmarshalCaddyfile(d.NewFromNextTokens())
				if err != nil {
					return err
				}
				sel, ok := unm.(Selector)
				if !ok {
					return d.Errf("module %s is not a Selector", mod)
				}
				if h.LoadBalancing == nil {
					h.LoadBalancing = new(LoadBalancing)
				}
				h.LoadBalancing.SelectionPolicyRaw = caddyconfig.JSONModuleObject(sel, "policy", name, nil)

			case "lb_try_duration":
				if !d.NextArg() {
					return d.ArgErr()
				}
				if h.LoadBalancing == nil {
					h.LoadBalancing = new(LoadBalancing)
				}
				dur, err := time.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("bad duration value %s: %v", d.Val(), err)
				}
				h.LoadBalancing.TryDuration = caddy.Duration(dur)

			case "lb_try_interval":
				if !d.NextArg() {
					return d.ArgErr()
				}
				if h.LoadBalancing == nil {
					h.LoadBalancing = new(LoadBalancing)
				}
				dur, err := time.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("bad interval value '%s': %v", d.Val(), err)
				}
				h.LoadBalancing.TryInterval = caddy.Duration(dur)

			case "health_path":
				if !d.NextArg() {
					return d.ArgErr()
				}
				if h.HealthChecks == nil {
					h.HealthChecks = new(HealthChecks)
				}
				if h.HealthChecks.Active == nil {
					h.HealthChecks.Active = new(ActiveHealthChecks)
				}
				h.HealthChecks.Active.Path = d.Val()

			case "health_port":
				if !d.NextArg() {
					return d.ArgErr()
				}
				if h.HealthChecks == nil {
					h.HealthChecks = new(HealthChecks)
				}
				if h.HealthChecks.Active == nil {
					h.HealthChecks.Active = new(ActiveHealthChecks)
				}
				portNum, err := strconv.Atoi(d.Val())
				if err != nil {
					return d.Errf("bad port number '%s': %v", d.Val(), err)
				}
				h.HealthChecks.Active.Port = portNum

			case "health_interval":
				if !d.NextArg() {
					return d.ArgErr()
				}
				if h.HealthChecks == nil {
					h.HealthChecks = new(HealthChecks)
				}
				if h.HealthChecks.Active == nil {
					h.HealthChecks.Active = new(ActiveHealthChecks)
				}
				dur, err := time.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("bad interval value %s: %v", d.Val(), err)
				}
				h.HealthChecks.Active.Interval = caddy.Duration(dur)

			case "health_timeout":
				if !d.NextArg() {
					return d.ArgErr()
				}
				if h.HealthChecks == nil {
					h.HealthChecks = new(HealthChecks)
				}
				if h.HealthChecks.Active == nil {
					h.HealthChecks.Active = new(ActiveHealthChecks)
				}
				dur, err := time.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("bad timeout value %s: %v", d.Val(), err)
				}
				h.HealthChecks.Active.Timeout = caddy.Duration(dur)

			case "health_status":
				if !d.NextArg() {
					return d.ArgErr()
				}
				if h.HealthChecks == nil {
					h.HealthChecks = new(HealthChecks)
				}
				if h.HealthChecks.Active == nil {
					h.HealthChecks.Active = new(ActiveHealthChecks)
				}
				val := d.Val()
				if len(val) == 3 && strings.HasSuffix(val, "xx") {
					val = val[:1]
				}
				statusNum, err := strconv.Atoi(val[:1])
				if err != nil {
					return d.Errf("bad status value '%s': %v", d.Val(), err)
				}
				h.HealthChecks.Active.ExpectStatus = statusNum

			case "health_body":
				if !d.NextArg() {
					return d.ArgErr()
				}
				if h.HealthChecks == nil {
					h.HealthChecks = new(HealthChecks)
				}
				if h.HealthChecks.Active == nil {
					h.HealthChecks.Active = new(ActiveHealthChecks)
				}
				h.HealthChecks.Active.ExpectBody = d.Val()

			case "max_fails":
				if !d.NextArg() {
					return d.ArgErr()
				}
				if h.HealthChecks == nil {
					h.HealthChecks = new(HealthChecks)
				}
				if h.HealthChecks.Passive == nil {
					h.HealthChecks.Passive = new(PassiveHealthChecks)
				}
				maxFails, err := strconv.Atoi(d.Val())
				if err != nil {
					return d.Errf("invalid maximum fail count '%s': %v", d.Val(), err)
				}
				h.HealthChecks.Passive.MaxFails = maxFails

			case "fail_duration":
				if !d.NextArg() {
					return d.ArgErr()
				}
				if h.HealthChecks == nil {
					h.HealthChecks = new(HealthChecks)
				}
				if h.HealthChecks.Passive == nil {
					h.HealthChecks.Passive = new(PassiveHealthChecks)
				}
				dur, err := time.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("bad duration value '%s': %v", d.Val(), err)
				}
				h.HealthChecks.Passive.FailDuration = caddy.Duration(dur)

			case "unhealthy_request_count":
				if !d.NextArg() {
					return d.ArgErr()
				}
				if h.HealthChecks == nil {
					h.HealthChecks = new(HealthChecks)
				}
				if h.HealthChecks.Passive == nil {
					h.HealthChecks.Passive = new(PassiveHealthChecks)
				}
				maxConns, err := strconv.Atoi(d.Val())
				if err != nil {
					return d.Errf("invalid maximum connection count '%s': %v", d.Val(), err)
				}
				h.HealthChecks.Passive.UnhealthyRequestCount = maxConns

			case "unhealthy_status":
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}
				if h.HealthChecks == nil {
					h.HealthChecks = new(HealthChecks)
				}
				if h.HealthChecks.Passive == nil {
					h.HealthChecks.Passive = new(PassiveHealthChecks)
				}
				for _, arg := range args {
					if len(arg) == 3 && strings.HasSuffix(arg, "xx") {
						arg = arg[:1]
					}
					statusNum, err := strconv.Atoi(arg[:1])
					if err != nil {
						return d.Errf("bad status value '%s': %v", d.Val(), err)
					}
					h.HealthChecks.Passive.UnhealthyStatus = append(h.HealthChecks.Passive.UnhealthyStatus, statusNum)
				}

			case "unhealthy_latency":
				if !d.NextArg() {
					return d.ArgErr()
				}
				if h.HealthChecks == nil {
					h.HealthChecks = new(HealthChecks)
				}
				if h.HealthChecks.Passive == nil {
					h.HealthChecks.Passive = new(PassiveHealthChecks)
				}
				dur, err := time.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("bad duration value '%s': %v", d.Val(), err)
				}
				h.HealthChecks.Passive.UnhealthyLatency = caddy.Duration(dur)

			case "flush_interval":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := time.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("bad duration value '%s': %v", d.Val(), err)
				}
				h.FlushInterval = caddy.Duration(dur)

			case "header_up":
				if h.Headers == nil {
					h.Headers = new(headers.Handler)
				}
				if h.Headers.Request == nil {
					h.Headers.Request = new(headers.HeaderOps)
				}
				args := d.RemainingArgs()
				switch len(args) {
				case 1:
					headers.CaddyfileHeaderOp(h.Headers.Request, args[0], "", "")
				case 2:
					headers.CaddyfileHeaderOp(h.Headers.Request, args[0], args[1], "")
				case 3:
					headers.CaddyfileHeaderOp(h.Headers.Request, args[0], args[1], args[2])
				default:
					return d.ArgErr()
				}

			case "header_down":
				if h.Headers == nil {
					h.Headers = new(headers.Handler)
				}
				if h.Headers.Response == nil {
					h.Headers.Response = &headers.RespHeaderOps{
						HeaderOps: new(headers.HeaderOps),
					}
				}
				args := d.RemainingArgs()
				switch len(args) {
				case 1:
					headers.CaddyfileHeaderOp(h.Headers.Response.HeaderOps, args[0], "", "")
				case 2:
					headers.CaddyfileHeaderOp(h.Headers.Response.HeaderOps, args[0], args[1], "")
				case 3:
					headers.CaddyfileHeaderOp(h.Headers.Response.HeaderOps, args[0], args[1], args[2])
				default:
					return d.ArgErr()
				}

			case "transport":
				if !d.NextArg() {
					return d.ArgErr()
				}
				if h.TransportRaw != nil {
					return d.Err("transport already specified")
				}
				name := d.Val()
				mod, err := caddy.GetModule("http.reverse_proxy.transport." + name)
				if err != nil {
					return d.Errf("getting transport module '%s': %v", mod, err)
				}
				unm, ok := mod.New().(caddyfile.Unmarshaler)
				if !ok {
					return d.Errf("transport module '%s' is not a Caddyfile unmarshaler", mod)
				}
				err = unm.UnmarshalCaddyfile(d.NewFromNextTokens())
				if err != nil {
					return err
				}
				rt, ok := unm.(http.RoundTripper)
				if !ok {
					return d.Errf("module %s is not a RoundTripper", mod)
				}
				h.TransportRaw = caddyconfig.JSONModuleObject(rt, "protocol", name, nil)

			default:
				return d.Errf("unrecognized subdirective %s", d.Val())
			}
		}
	}

	return nil
}

// UnmarshalCaddyfile deserializes Caddyfile tokens into h.
//
//     transport http {
//         read_buffer  <size>
//         write_buffer <size>
//         dial_timeout <duration>
//         tls_client_auth <cert_file> <key_file>
//         tls_insecure_skip_verify
//         tls_timeout <duration>
//         keepalive [off|<duration>]
//         keepalive_idle_conns <max_count>
//     }
//
func (h *HTTPTransport) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "read_buffer":
				if !d.NextArg() {
					return d.ArgErr()
				}
				size, err := humanize.ParseBytes(d.Val())
				if err != nil {
					return d.Errf("invalid read buffer size '%s': %v", d.Val(), err)
				}
				h.ReadBufferSize = int(size)

			case "write_buffer":
				if !d.NextArg() {
					return d.ArgErr()
				}
				size, err := humanize.ParseBytes(d.Val())
				if err != nil {
					return d.Errf("invalid write buffer size '%s': %v", d.Val(), err)
				}
				h.WriteBufferSize = int(size)

			case "dial_timeout":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := time.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("bad timeout value '%s': %v", d.Val(), err)
				}
				h.DialTimeout = caddy.Duration(dur)

			case "tls_client_auth":
				args := d.RemainingArgs()
				if len(args) != 2 {
					return d.ArgErr()
				}
				if h.TLS == nil {
					h.TLS = new(TLSConfig)
				}
				h.TLS.ClientCertificateFile = args[0]
				h.TLS.ClientCertificateKeyFile = args[1]

			case "tls":
				if h.TLS == nil {
					h.TLS = new(TLSConfig)
				}

			case "tls_insecure_skip_verify":
				if d.NextArg() {
					return d.ArgErr()
				}
				if h.TLS == nil {
					h.TLS = new(TLSConfig)
				}
				h.TLS.InsecureSkipVerify = true

			case "tls_timeout":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := time.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("bad timeout value '%s': %v", d.Val(), err)
				}
				if h.TLS == nil {
					h.TLS = new(TLSConfig)
				}
				h.TLS.HandshakeTimeout = caddy.Duration(dur)

			case "keepalive":
				if !d.NextArg() {
					return d.ArgErr()
				}
				if h.KeepAlive == nil {
					h.KeepAlive = new(KeepAlive)
				}
				if d.Val() == "off" {
					var disable bool
					h.KeepAlive.Enabled = &disable
					break
				}
				dur, err := time.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("bad duration value '%s': %v", d.Val(), err)
				}
				h.KeepAlive.IdleConnTimeout = caddy.Duration(dur)

			case "keepalive_idle_conns":
				if !d.NextArg() {
					return d.ArgErr()
				}
				num, err := strconv.Atoi(d.Val())
				if err != nil {
					return d.Errf("bad integer value '%s': %v", d.Val(), err)
				}
				if h.KeepAlive == nil {
					h.KeepAlive = new(KeepAlive)
				}
				h.KeepAlive.MaxIdleConns = num
				h.KeepAlive.MaxIdleConnsPerHost = num

			default:
				return d.Errf("unrecognized subdirective %s", d.Val())
			}
		}
	}
	return nil
}

// Interface guards
var (
	_ caddyfile.Unmarshaler = (*Handler)(nil)
	_ caddyfile.Unmarshaler = (*HTTPTransport)(nil)
)
