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
	"fmt"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	"github.com/dustin/go-humanize"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/internal"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/headers"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/rewrite"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("reverse_proxy", parseCaddyfile)
	httpcaddyfile.RegisterHandlerDirective("copy_response", parseCopyResponseCaddyfile)
	httpcaddyfile.RegisterHandlerDirective("copy_response_headers", parseCopyResponseHeadersCaddyfile)
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	rp := new(Handler)
	err := rp.UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		return nil, err
	}
	err = rp.FinalizeUnmarshalCaddyfile(h)
	if err != nil {
		return nil, err
	}
	return rp, nil
}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens. Syntax:
//
//	reverse_proxy [<matcher>] [<upstreams...>] {
//	    # backends
//	    to      <upstreams...>
//	    dynamic <name> [...]
//
//	    # load balancing
//	    lb_policy <name> [<options...>]
//	    lb_retries <retries>
//	    lb_try_duration <duration>
//	    lb_try_interval <interval>
//	    lb_retry_match <request-matcher>
//
//	    # active health checking
//	    health_uri          <uri>
//	    health_port         <port>
//	    health_interval     <interval>
//	    health_passes       <num>
//	    health_fails        <num>
//	    health_timeout      <duration>
//	    health_status       <status>
//	    health_body         <regexp>
//	    health_method       <value>
//	    health_request_body <value>
//	    health_follow_redirects
//	    health_headers {
//	        <field> [<values...>]
//	    }
//
//	    # passive health checking
//	    fail_duration     <duration>
//	    max_fails         <num>
//	    unhealthy_status  <status>
//	    unhealthy_latency <duration>
//	    unhealthy_request_count <num>
//
//	    # streaming
//	    flush_interval     <duration>
//	    request_buffers    <size>
//	    response_buffers   <size>
//	    stream_timeout     <duration>
//	    stream_close_delay <duration>
//	    verbose_logs
//
//	    # request manipulation
//	    trusted_proxies [private_ranges] <ranges...>
//	    header_up   [+|-]<field> [<value|regexp> [<replacement>]]
//	    header_down [+|-]<field> [<value|regexp> [<replacement>]]
//	    method <method>
//	    rewrite <to>
//
//	    # round trip
//	    transport <name> {
//	        ...
//	    }
//
//	    # optionally intercept responses from upstream
//	    @name {
//	        status <code...>
//	        header <field> [<value>]
//	    }
//	    replace_status [<matcher>] <status_code>
//	    handle_response [<matcher>] {
//	        <directives...>
//
//	        # special directives only available in handle_response
//	        copy_response [<matcher>] [<status>] {
//	            status <status>
//	        }
//	        copy_response_headers [<matcher>] {
//	            include <fields...>
//	            exclude <fields...>
//	        }
//	    }
//	}
//
// Proxy upstream addresses should be network dial addresses such
// as `host:port`, or a URL such as `scheme://host:port`. Scheme
// and port may be inferred from other parts of the address/URL; if
// either are missing, defaults to HTTP.
//
// The FinalizeUnmarshalCaddyfile method should be called after this
// to finalize parsing of "handle_response" blocks, if possible.
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// currently, all backends must use the same scheme/protocol (the
	// underlying JSON does not yet support per-backend transports)
	var commonScheme string

	// we'll wait until the very end of parsing before
	// validating and encoding the transport
	var transport http.RoundTripper
	var transportModuleName string

	// collect the response matchers defined as subdirectives
	// prefixed with "@" for use with "handle_response" blocks
	h.responseMatchers = make(map[string]caddyhttp.ResponseMatcher)

	// appendUpstream creates an upstream for address and adds
	// it to the list.
	appendUpstream := func(address string) error {
		pa, err := parseUpstreamDialAddress(address)
		if err != nil {
			return d.WrapErr(err)
		}

		// the underlying JSON does not yet support different
		// transports (protocols or schemes) to each backend,
		// so we remember the last one we see and compare them

		switch pa.scheme {
		case "wss":
			return d.Errf("the scheme wss:// is only supported in browsers; use https:// instead")
		case "ws":
			return d.Errf("the scheme ws:// is only supported in browsers; use http:// instead")
		case "https", "http", "h2c", "":
			// Do nothing or handle the valid schemes
		default:
			return d.Errf("unsupported URL scheme %s://", pa.scheme)
		}

		if commonScheme != "" && pa.scheme != commonScheme {
			return d.Errf("for now, all proxy upstreams must use the same scheme (transport protocol); expecting '%s://' but got '%s://'",
				commonScheme, pa.scheme)
		}
		commonScheme = pa.scheme

		// if the port of upstream address contains a placeholder, only wrap it with the `Upstream` struct,
		// delaying actual resolution of the address until request time.
		if pa.replaceablePort() {
			h.Upstreams = append(h.Upstreams, &Upstream{Dial: pa.dialAddr()})
			return nil
		}
		parsedAddr, err := caddy.ParseNetworkAddress(pa.dialAddr())
		if err != nil {
			return d.WrapErr(err)
		}

		if pa.isUnix() || !pa.rangedPort() {
			// unix networks don't have ports
			h.Upstreams = append(h.Upstreams, &Upstream{
				Dial: pa.dialAddr(),
			})
		} else {
			// expand a port range into multiple upstreams
			for i := parsedAddr.StartPort; i <= parsedAddr.EndPort; i++ {
				h.Upstreams = append(h.Upstreams, &Upstream{
					Dial: caddy.JoinNetworkAddress("", parsedAddr.Host, fmt.Sprint(i)),
				})
			}
		}

		return nil
	}

	d.Next() // consume the directive name
	for _, up := range d.RemainingArgs() {
		err := appendUpstream(up)
		if err != nil {
			return fmt.Errorf("parsing upstream '%s': %w", up, err)
		}
	}

	for d.NextBlock(0) {
		// if the subdirective has an "@" prefix then we
		// parse it as a response matcher for use with "handle_response"
		if strings.HasPrefix(d.Val(), matcherPrefix) {
			err := caddyhttp.ParseNamedResponseMatcher(d.NewFromNextSegment(), h.responseMatchers)
			if err != nil {
				return err
			}
			continue
		}

		switch d.Val() {
		case "to":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			for _, up := range args {
				err := appendUpstream(up)
				if err != nil {
					return fmt.Errorf("parsing upstream '%s': %w", up, err)
				}
			}

		case "dynamic":
			if !d.NextArg() {
				return d.ArgErr()
			}
			if h.DynamicUpstreams != nil {
				return d.Err("dynamic upstreams already specified")
			}
			dynModule := d.Val()
			modID := "http.reverse_proxy.upstreams." + dynModule
			unm, err := caddyfile.UnmarshalModule(d, modID)
			if err != nil {
				return err
			}
			source, ok := unm.(UpstreamSource)
			if !ok {
				return d.Errf("module %s (%T) is not an UpstreamSource", modID, unm)
			}
			h.DynamicUpstreamsRaw = caddyconfig.JSONModuleObject(source, "source", dynModule, nil)

		case "lb_policy":
			if !d.NextArg() {
				return d.ArgErr()
			}
			if h.LoadBalancing != nil && h.LoadBalancing.SelectionPolicyRaw != nil {
				return d.Err("load balancing selection policy already specified")
			}
			name := d.Val()
			modID := "http.reverse_proxy.selection_policies." + name
			unm, err := caddyfile.UnmarshalModule(d, modID)
			if err != nil {
				return err
			}
			sel, ok := unm.(Selector)
			if !ok {
				return d.Errf("module %s (%T) is not a reverseproxy.Selector", modID, unm)
			}
			if h.LoadBalancing == nil {
				h.LoadBalancing = new(LoadBalancing)
			}
			h.LoadBalancing.SelectionPolicyRaw = caddyconfig.JSONModuleObject(sel, "policy", name, nil)

		case "lb_retries":
			if !d.NextArg() {
				return d.ArgErr()
			}
			tries, err := strconv.Atoi(d.Val())
			if err != nil {
				return d.Errf("bad lb_retries number '%s': %v", d.Val(), err)
			}
			if h.LoadBalancing == nil {
				h.LoadBalancing = new(LoadBalancing)
			}
			h.LoadBalancing.Retries = tries

		case "lb_try_duration":
			if !d.NextArg() {
				return d.ArgErr()
			}
			if h.LoadBalancing == nil {
				h.LoadBalancing = new(LoadBalancing)
			}
			dur, err := caddy.ParseDuration(d.Val())
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
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("bad interval value '%s': %v", d.Val(), err)
			}
			h.LoadBalancing.TryInterval = caddy.Duration(dur)

		case "lb_retry_match":
			matcherSet, err := caddyhttp.ParseCaddyfileNestedMatcherSet(d)
			if err != nil {
				return d.Errf("failed to parse lb_retry_match: %v", err)
			}
			if h.LoadBalancing == nil {
				h.LoadBalancing = new(LoadBalancing)
			}
			h.LoadBalancing.RetryMatchRaw = append(h.LoadBalancing.RetryMatchRaw, matcherSet)

		case "health_uri":
			if !d.NextArg() {
				return d.ArgErr()
			}
			if h.HealthChecks == nil {
				h.HealthChecks = new(HealthChecks)
			}
			if h.HealthChecks.Active == nil {
				h.HealthChecks.Active = new(ActiveHealthChecks)
			}
			h.HealthChecks.Active.URI = d.Val()

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
			caddy.Log().Named("config.adapter.caddyfile").Warn("the 'health_path' subdirective is deprecated, please use 'health_uri' instead!")

		case "health_upstream":
			if !d.NextArg() {
				return d.ArgErr()
			}
			if h.HealthChecks == nil {
				h.HealthChecks = new(HealthChecks)
			}
			if h.HealthChecks.Active == nil {
				h.HealthChecks.Active = new(ActiveHealthChecks)
			}
			_, port, err := net.SplitHostPort(d.Val())
			if err != nil {
				return d.Errf("health_upstream is malformed '%s': %v", d.Val(), err)
			}
			_, err = strconv.Atoi(port)
			if err != nil {
				return d.Errf("bad port number '%s': %v", d.Val(), err)
			}
			h.HealthChecks.Active.Upstream = d.Val()

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
			if h.HealthChecks.Active.Upstream != "" {
				return d.Errf("the 'health_port' subdirective is ignored if 'health_upstream' is used!")
			}
			portNum, err := strconv.Atoi(d.Val())
			if err != nil {
				return d.Errf("bad port number '%s': %v", d.Val(), err)
			}
			h.HealthChecks.Active.Port = portNum

		case "health_headers":
			healthHeaders := make(http.Header)
			for nesting := d.Nesting(); d.NextBlock(nesting); {
				key := d.Val()
				values := d.RemainingArgs()
				if len(values) == 0 {
					values = append(values, "")
				}
				healthHeaders[key] = append(healthHeaders[key], values...)
			}
			if h.HealthChecks == nil {
				h.HealthChecks = new(HealthChecks)
			}
			if h.HealthChecks.Active == nil {
				h.HealthChecks.Active = new(ActiveHealthChecks)
			}
			h.HealthChecks.Active.Headers = healthHeaders

		case "health_method":
			if !d.NextArg() {
				return d.ArgErr()
			}
			if h.HealthChecks == nil {
				h.HealthChecks = new(HealthChecks)
			}
			if h.HealthChecks.Active == nil {
				h.HealthChecks.Active = new(ActiveHealthChecks)
			}
			h.HealthChecks.Active.Method = d.Val()

		case "health_request_body":
			if !d.NextArg() {
				return d.ArgErr()
			}
			if h.HealthChecks == nil {
				h.HealthChecks = new(HealthChecks)
			}
			if h.HealthChecks.Active == nil {
				h.HealthChecks.Active = new(ActiveHealthChecks)
			}
			h.HealthChecks.Active.Body = d.Val()

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
			dur, err := caddy.ParseDuration(d.Val())
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
			dur, err := caddy.ParseDuration(d.Val())
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
			statusNum, err := strconv.Atoi(val)
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

		case "health_follow_redirects":
			if d.NextArg() {
				return d.ArgErr()
			}
			if h.HealthChecks == nil {
				h.HealthChecks = new(HealthChecks)
			}
			if h.HealthChecks.Active == nil {
				h.HealthChecks.Active = new(ActiveHealthChecks)
			}
			h.HealthChecks.Active.FollowRedirects = true

		case "health_passes":
			if !d.NextArg() {
				return d.ArgErr()
			}
			if h.HealthChecks == nil {
				h.HealthChecks = new(HealthChecks)
			}
			if h.HealthChecks.Active == nil {
				h.HealthChecks.Active = new(ActiveHealthChecks)
			}
			passes, err := strconv.Atoi(d.Val())
			if err != nil {
				return d.Errf("invalid passes count '%s': %v", d.Val(), err)
			}
			h.HealthChecks.Active.Passes = passes

		case "health_fails":
			if !d.NextArg() {
				return d.ArgErr()
			}
			if h.HealthChecks == nil {
				h.HealthChecks = new(HealthChecks)
			}
			if h.HealthChecks.Active == nil {
				h.HealthChecks.Active = new(ActiveHealthChecks)
			}
			fails, err := strconv.Atoi(d.Val())
			if err != nil {
				return d.Errf("invalid fails count '%s': %v", d.Val(), err)
			}
			h.HealthChecks.Active.Fails = fails

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
			dur, err := caddy.ParseDuration(d.Val())
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
				statusNum, err := strconv.Atoi(arg)
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
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("bad duration value '%s': %v", d.Val(), err)
			}
			h.HealthChecks.Passive.UnhealthyLatency = caddy.Duration(dur)

		case "flush_interval":
			if !d.NextArg() {
				return d.ArgErr()
			}
			if fi, err := strconv.Atoi(d.Val()); err == nil {
				h.FlushInterval = caddy.Duration(fi)
			} else {
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("bad duration value '%s': %v", d.Val(), err)
				}
				h.FlushInterval = caddy.Duration(dur)
			}

		case "request_buffers", "response_buffers":
			subdir := d.Val()
			if !d.NextArg() {
				return d.ArgErr()
			}
			val := d.Val()
			var size int64
			if val == "unlimited" {
				size = -1
			} else {
				usize, err := humanize.ParseBytes(val)
				if err != nil {
					return d.Errf("invalid byte size '%s': %v", val, err)
				}
				size = int64(usize)
			}
			if d.NextArg() {
				return d.ArgErr()
			}
			if subdir == "request_buffers" {
				h.RequestBuffers = size
			} else if subdir == "response_buffers" {
				h.ResponseBuffers = size
			}

		case "stream_timeout":
			if !d.NextArg() {
				return d.ArgErr()
			}
			if fi, err := strconv.Atoi(d.Val()); err == nil {
				h.StreamTimeout = caddy.Duration(fi)
			} else {
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("bad duration value '%s': %v", d.Val(), err)
				}
				h.StreamTimeout = caddy.Duration(dur)
			}

		case "stream_close_delay":
			if !d.NextArg() {
				return d.ArgErr()
			}
			if fi, err := strconv.Atoi(d.Val()); err == nil {
				h.StreamCloseDelay = caddy.Duration(fi)
			} else {
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("bad duration value '%s': %v", d.Val(), err)
				}
				h.StreamCloseDelay = caddy.Duration(dur)
			}

		case "trusted_proxies":
			for d.NextArg() {
				if d.Val() == "private_ranges" {
					h.TrustedProxies = append(h.TrustedProxies, internal.PrivateRangesCIDR()...)
					continue
				}
				h.TrustedProxies = append(h.TrustedProxies, d.Val())
			}

		case "header_up":
			var err error

			if h.Headers == nil {
				h.Headers = new(headers.Handler)
			}
			if h.Headers.Request == nil {
				h.Headers.Request = new(headers.HeaderOps)
			}
			args := d.RemainingArgs()

			switch len(args) {
			case 1:
				err = headers.CaddyfileHeaderOp(h.Headers.Request, args[0], "", nil)
			case 2:
				// some lint checks, I guess
				if strings.EqualFold(args[0], "host") && (args[1] == "{hostport}" || args[1] == "{http.request.hostport}") {
					caddy.Log().Named("caddyfile").Warn("Unnecessary header_up Host: the reverse proxy's default behavior is to pass headers to the upstream")
				}
				if strings.EqualFold(args[0], "x-forwarded-for") && (args[1] == "{remote}" || args[1] == "{http.request.remote}" || args[1] == "{remote_host}" || args[1] == "{http.request.remote.host}") {
					caddy.Log().Named("caddyfile").Warn("Unnecessary header_up X-Forwarded-For: the reverse proxy's default behavior is to pass headers to the upstream")
				}
				if strings.EqualFold(args[0], "x-forwarded-proto") && (args[1] == "{scheme}" || args[1] == "{http.request.scheme}") {
					caddy.Log().Named("caddyfile").Warn("Unnecessary header_up X-Forwarded-Proto: the reverse proxy's default behavior is to pass headers to the upstream")
				}
				if strings.EqualFold(args[0], "x-forwarded-host") && (args[1] == "{host}" || args[1] == "{http.request.host}" || args[1] == "{hostport}" || args[1] == "{http.request.hostport}") {
					caddy.Log().Named("caddyfile").Warn("Unnecessary header_up X-Forwarded-Host: the reverse proxy's default behavior is to pass headers to the upstream")
				}
				err = headers.CaddyfileHeaderOp(h.Headers.Request, args[0], args[1], nil)
			case 3:
				err = headers.CaddyfileHeaderOp(h.Headers.Request, args[0], args[1], &args[2])
			default:
				return d.ArgErr()
			}

			if err != nil {
				return d.Err(err.Error())
			}

		case "header_down":
			var err error

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
				err = headers.CaddyfileHeaderOp(h.Headers.Response.HeaderOps, args[0], "", nil)
			case 2:
				err = headers.CaddyfileHeaderOp(h.Headers.Response.HeaderOps, args[0], args[1], nil)
			case 3:
				err = headers.CaddyfileHeaderOp(h.Headers.Response.HeaderOps, args[0], args[1], &args[2])
			default:
				return d.ArgErr()
			}

			if err != nil {
				return d.Err(err.Error())
			}

		case "method":
			if !d.NextArg() {
				return d.ArgErr()
			}
			if h.Rewrite == nil {
				h.Rewrite = &rewrite.Rewrite{}
			}
			h.Rewrite.Method = d.Val()
			if d.NextArg() {
				return d.ArgErr()
			}

		case "rewrite":
			if !d.NextArg() {
				return d.ArgErr()
			}
			if h.Rewrite == nil {
				h.Rewrite = &rewrite.Rewrite{}
			}
			h.Rewrite.URI = d.Val()
			if d.NextArg() {
				return d.ArgErr()
			}

		case "transport":
			if !d.NextArg() {
				return d.ArgErr()
			}
			if h.TransportRaw != nil {
				return d.Err("transport already specified")
			}
			transportModuleName = d.Val()
			modID := "http.reverse_proxy.transport." + transportModuleName
			unm, err := caddyfile.UnmarshalModule(d, modID)
			if err != nil {
				return err
			}
			rt, ok := unm.(http.RoundTripper)
			if !ok {
				return d.Errf("module %s (%T) is not a RoundTripper", modID, unm)
			}
			transport = rt

		case "handle_response":
			// delegate the parsing of handle_response to the caller,
			// since we need the httpcaddyfile.Helper to parse subroutes.
			// See h.FinalizeUnmarshalCaddyfile
			h.handleResponseSegments = append(h.handleResponseSegments, d.NewFromNextSegment())

		case "replace_status":
			args := d.RemainingArgs()
			if len(args) != 1 && len(args) != 2 {
				return d.Errf("must have one or two arguments: an optional response matcher, and a status code")
			}

			responseHandler := caddyhttp.ResponseHandler{}

			if len(args) == 2 {
				if !strings.HasPrefix(args[0], matcherPrefix) {
					return d.Errf("must use a named response matcher, starting with '@'")
				}
				foundMatcher, ok := h.responseMatchers[args[0]]
				if !ok {
					return d.Errf("no named response matcher defined with name '%s'", args[0][1:])
				}
				responseHandler.Match = &foundMatcher
				responseHandler.StatusCode = caddyhttp.WeakString(args[1])
			} else if len(args) == 1 {
				responseHandler.StatusCode = caddyhttp.WeakString(args[0])
			}

			// make sure there's no block, cause it doesn't make sense
			if nesting := d.Nesting(); d.NextBlock(nesting) {
				return d.Errf("cannot define routes for 'replace_status', use 'handle_response' instead.")
			}

			h.HandleResponse = append(
				h.HandleResponse,
				responseHandler,
			)

		case "verbose_logs":
			if h.VerboseLogs {
				return d.Err("verbose_logs already specified")
			}
			h.VerboseLogs = true

		default:
			return d.Errf("unrecognized subdirective %s", d.Val())
		}
	}

	// if the scheme inferred from the backends' addresses is
	// HTTPS, we will need a non-nil transport to enable TLS,
	// or if H2C, to set the transport versions.
	if (commonScheme == "https" || commonScheme == "h2c") && transport == nil {
		transport = new(HTTPTransport)
		transportModuleName = "http"
	}

	// verify transport configuration, and finally encode it
	if transport != nil {
		if te, ok := transport.(TLSTransport); ok {
			if commonScheme == "https" && !te.TLSEnabled() {
				err := te.EnableTLS(new(TLSConfig))
				if err != nil {
					return err
				}
			}
			if commonScheme == "http" && te.TLSEnabled() {
				return d.Errf("upstream address scheme is HTTP but transport is configured for HTTP+TLS (HTTPS)")
			}
			if te, ok := transport.(*HTTPTransport); ok && commonScheme == "h2c" {
				te.Versions = []string{"h2c", "2"}
			}
		} else if commonScheme == "https" {
			return d.Errf("upstreams are configured for HTTPS but transport module does not support TLS: %T", transport)
		}

		// no need to encode empty default transport
		if !reflect.DeepEqual(transport, new(HTTPTransport)) {
			h.TransportRaw = caddyconfig.JSONModuleObject(transport, "protocol", transportModuleName, nil)
		}
	}

	return nil
}

// FinalizeUnmarshalCaddyfile finalizes the Caddyfile parsing which
// requires having an httpcaddyfile.Helper to function, to parse subroutes.
func (h *Handler) FinalizeUnmarshalCaddyfile(helper httpcaddyfile.Helper) error {
	for _, d := range h.handleResponseSegments {
		// consume the "handle_response" token
		d.Next()
		args := d.RemainingArgs()

		// TODO: Remove this check at some point in the future
		if len(args) == 2 {
			return d.Errf("configuring 'handle_response' for status code replacement is no longer supported. Use 'replace_status' instead.")
		}

		if len(args) > 1 {
			return d.Errf("too many arguments for 'handle_response': %s", args)
		}

		var matcher *caddyhttp.ResponseMatcher
		if len(args) == 1 {
			// the first arg should always be a matcher.
			if !strings.HasPrefix(args[0], matcherPrefix) {
				return d.Errf("must use a named response matcher, starting with '@'")
			}

			foundMatcher, ok := h.responseMatchers[args[0]]
			if !ok {
				return d.Errf("no named response matcher defined with name '%s'", args[0][1:])
			}
			matcher = &foundMatcher
		}

		// parse the block as routes
		handler, err := httpcaddyfile.ParseSegmentAsSubroute(helper.WithDispenser(d.NewFromNextSegment()))
		if err != nil {
			return err
		}
		subroute, ok := handler.(*caddyhttp.Subroute)
		if !ok {
			return helper.Errf("segment was not parsed as a subroute")
		}
		h.HandleResponse = append(
			h.HandleResponse,
			caddyhttp.ResponseHandler{
				Match:  matcher,
				Routes: subroute.Routes,
			},
		)
	}

	// move the handle_response entries without a matcher to the end.
	// we can't use sort.SliceStable because it will reorder the rest of the
	// entries which may be undesirable because we don't have a good
	// heuristic to use for sorting.
	withoutMatchers := []caddyhttp.ResponseHandler{}
	withMatchers := []caddyhttp.ResponseHandler{}
	for _, hr := range h.HandleResponse {
		if hr.Match == nil {
			withoutMatchers = append(withoutMatchers, hr)
		} else {
			withMatchers = append(withMatchers, hr)
		}
	}
	h.HandleResponse = append(withMatchers, withoutMatchers...)

	// clean up the bits we only needed for adapting
	h.handleResponseSegments = nil
	h.responseMatchers = nil

	return nil
}

// UnmarshalCaddyfile deserializes Caddyfile tokens into h.
//
//	transport http {
//	    read_buffer             <size>
//	    write_buffer            <size>
//	    max_response_header     <size>
//	    forward_proxy_url       <url>
//	    dial_timeout            <duration>
//	    dial_fallback_delay     <duration>
//	    response_header_timeout <duration>
//	    expect_continue_timeout <duration>
//	    resolvers               <resolvers...>
//	    tls
//	    tls_client_auth <automate_name> | <cert_file> <key_file>
//	    tls_insecure_skip_verify
//	    tls_timeout <duration>
//	    tls_trusted_ca_certs <cert_files...>
//	    tls_server_name <sni>
//	    tls_renegotiation <level>
//	    tls_except_ports <ports...>
//	    keepalive [off|<duration>]
//	    keepalive_interval <interval>
//	    keepalive_idle_conns <max_count>
//	    keepalive_idle_conns_per_host <count>
//	    versions <versions...>
//	    compression off
//	    max_conns_per_host <count>
//	    max_idle_conns_per_host <count>
//	}
func (h *HTTPTransport) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume transport name
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

		case "read_timeout":
			if !d.NextArg() {
				return d.ArgErr()
			}
			timeout, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("invalid read timeout duration '%s': %v", d.Val(), err)
			}
			h.ReadTimeout = caddy.Duration(timeout)

		case "write_timeout":
			if !d.NextArg() {
				return d.ArgErr()
			}
			timeout, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("invalid write timeout duration '%s': %v", d.Val(), err)
			}
			h.WriteTimeout = caddy.Duration(timeout)

		case "max_response_header":
			if !d.NextArg() {
				return d.ArgErr()
			}
			size, err := humanize.ParseBytes(d.Val())
			if err != nil {
				return d.Errf("invalid max response header size '%s': %v", d.Val(), err)
			}
			h.MaxResponseHeaderSize = int64(size)

		case "proxy_protocol":
			if !d.NextArg() {
				return d.ArgErr()
			}
			switch proxyProtocol := d.Val(); proxyProtocol {
			case "v1", "v2":
				h.ProxyProtocol = proxyProtocol
			default:
				return d.Errf("invalid proxy protocol version '%s'", proxyProtocol)
			}

		case "forward_proxy_url":
			if !d.NextArg() {
				return d.ArgErr()
			}
			h.ForwardProxyURL = d.Val()

		case "dial_timeout":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("bad timeout value '%s': %v", d.Val(), err)
			}
			h.DialTimeout = caddy.Duration(dur)

		case "dial_fallback_delay":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("bad fallback delay value '%s': %v", d.Val(), err)
			}
			h.FallbackDelay = caddy.Duration(dur)

		case "response_header_timeout":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("bad timeout value '%s': %v", d.Val(), err)
			}
			h.ResponseHeaderTimeout = caddy.Duration(dur)

		case "expect_continue_timeout":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("bad timeout value '%s': %v", d.Val(), err)
			}
			h.ExpectContinueTimeout = caddy.Duration(dur)

		case "resolvers":
			if h.Resolver == nil {
				h.Resolver = new(UpstreamResolver)
			}
			h.Resolver.Addresses = d.RemainingArgs()
			if len(h.Resolver.Addresses) == 0 {
				return d.Errf("must specify at least one resolver address")
			}

		case "tls":
			if h.TLS == nil {
				h.TLS = new(TLSConfig)
			}

		case "tls_client_auth":
			if h.TLS == nil {
				h.TLS = new(TLSConfig)
			}
			args := d.RemainingArgs()
			switch len(args) {
			case 1:
				h.TLS.ClientCertificateAutomate = args[0]
			case 2:
				h.TLS.ClientCertificateFile = args[0]
				h.TLS.ClientCertificateKeyFile = args[1]
			default:
				return d.ArgErr()
			}

		case "tls_insecure_skip_verify":
			if d.NextArg() {
				return d.ArgErr()
			}
			if h.TLS == nil {
				h.TLS = new(TLSConfig)
			}
			h.TLS.InsecureSkipVerify = true

		case "tls_curves":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			if h.TLS == nil {
				h.TLS = new(TLSConfig)
			}
			h.TLS.Curves = args

		case "tls_timeout":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("bad timeout value '%s': %v", d.Val(), err)
			}
			if h.TLS == nil {
				h.TLS = new(TLSConfig)
			}
			h.TLS.HandshakeTimeout = caddy.Duration(dur)

		case "tls_trusted_ca_certs":
			caddy.Log().Warn("The 'tls_trusted_ca_certs' field is deprecated. Use the 'tls_trust_pool' field instead.")
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			if h.TLS == nil {
				h.TLS = new(TLSConfig)
			}
			if len(h.TLS.CARaw) != 0 {
				return d.Err("cannot specify both 'tls_trust_pool' and 'tls_trusted_ca_certs")
			}
			h.TLS.RootCAPEMFiles = args

		case "tls_server_name":
			if !d.NextArg() {
				return d.ArgErr()
			}
			if h.TLS == nil {
				h.TLS = new(TLSConfig)
			}
			h.TLS.ServerName = d.Val()

		case "tls_renegotiation":
			if h.TLS == nil {
				h.TLS = new(TLSConfig)
			}
			if !d.NextArg() {
				return d.ArgErr()
			}
			switch renegotiation := d.Val(); renegotiation {
			case "never", "once", "freely":
				h.TLS.Renegotiation = renegotiation
			default:
				return d.ArgErr()
			}

		case "tls_except_ports":
			if h.TLS == nil {
				h.TLS = new(TLSConfig)
			}
			h.TLS.ExceptPorts = d.RemainingArgs()
			if len(h.TLS.ExceptPorts) == 0 {
				return d.ArgErr()
			}

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
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("bad duration value '%s': %v", d.Val(), err)
			}
			h.KeepAlive.IdleConnTimeout = caddy.Duration(dur)

		case "keepalive_interval":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("bad interval value '%s': %v", d.Val(), err)
			}
			if h.KeepAlive == nil {
				h.KeepAlive = new(KeepAlive)
			}
			h.KeepAlive.ProbeInterval = caddy.Duration(dur)

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

		case "keepalive_idle_conns_per_host":
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
			h.KeepAlive.MaxIdleConnsPerHost = num

		case "versions":
			h.Versions = d.RemainingArgs()
			if len(h.Versions) == 0 {
				return d.ArgErr()
			}

		case "compression":
			if d.NextArg() {
				if d.Val() == "off" {
					var disable bool
					h.Compression = &disable
				}
			}

		case "max_conns_per_host":
			if !d.NextArg() {
				return d.ArgErr()
			}
			num, err := strconv.Atoi(d.Val())
			if err != nil {
				return d.Errf("bad integer value '%s': %v", d.Val(), err)
			}
			h.MaxConnsPerHost = num

		case "tls_trust_pool":
			if !d.NextArg() {
				return d.ArgErr()
			}
			modStem := d.Val()
			modID := "tls.ca_pool.source." + modStem
			unm, err := caddyfile.UnmarshalModule(d, modID)
			if err != nil {
				return err
			}
			ca, ok := unm.(caddytls.CA)
			if !ok {
				return d.Errf("module %s is not a caddytls.CA", modID)
			}
			if h.TLS == nil {
				h.TLS = new(TLSConfig)
			}
			if len(h.TLS.RootCAPEMFiles) != 0 {
				return d.Err("cannot specify both 'tls_trust_pool' and 'tls_trusted_ca_certs'")
			}
			if h.TLS.CARaw != nil {
				return d.Err("cannot specify \"tls_trust_pool\" twice in caddyfile")
			}
			h.TLS.CARaw = caddyconfig.JSONModuleObject(ca, "provider", modStem, nil)
		case "local_address":
			if !d.NextArg() {
				return d.ArgErr()
			}
			h.LocalAddress = d.Val()
		default:
			return d.Errf("unrecognized subdirective %s", d.Val())
		}
	}
	return nil
}

func parseCopyResponseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	crh := new(CopyResponseHandler)
	err := crh.UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		return nil, err
	}
	return crh, nil
}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens. Syntax:
//
//	copy_response [<matcher>] [<status>] {
//	    status <status>
//	}
func (h *CopyResponseHandler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name

	args := d.RemainingArgs()
	if len(args) == 1 {
		if num, err := strconv.Atoi(args[0]); err == nil && num > 0 {
			h.StatusCode = caddyhttp.WeakString(args[0])
			return nil
		}
	}

	for d.NextBlock(0) {
		switch d.Val() {
		case "status":
			if !d.NextArg() {
				return d.ArgErr()
			}
			h.StatusCode = caddyhttp.WeakString(d.Val())
		default:
			return d.Errf("unrecognized subdirective '%s'", d.Val())
		}
	}
	return nil
}

func parseCopyResponseHeadersCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	crh := new(CopyResponseHeadersHandler)
	err := crh.UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		return nil, err
	}
	return crh, nil
}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens. Syntax:
//
//	copy_response_headers [<matcher>] {
//	    include <fields...>
//	    exclude <fields...>
//	}
func (h *CopyResponseHeadersHandler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name

	args := d.RemainingArgs()
	if len(args) > 0 {
		return d.ArgErr()
	}

	for d.NextBlock(0) {
		switch d.Val() {
		case "include":
			h.Include = append(h.Include, d.RemainingArgs()...)

		case "exclude":
			h.Exclude = append(h.Exclude, d.RemainingArgs()...)

		default:
			return d.Errf("unrecognized subdirective '%s'", d.Val())
		}
	}
	return nil
}

// UnmarshalCaddyfile deserializes Caddyfile tokens into h.
//
//	dynamic srv [<name>] {
//	    service             <service>
//	    proto               <proto>
//	    name                <name>
//	    refresh             <interval>
//	    resolvers           <resolvers...>
//	    dial_timeout        <timeout>
//	    dial_fallback_delay <timeout>
//	    grace_period        <duration>
//	}
func (u *SRVUpstreams) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume upstream source name

	args := d.RemainingArgs()
	if len(args) > 1 {
		return d.ArgErr()
	}
	if len(args) > 0 {
		u.Name = args[0]
	}

	for d.NextBlock(0) {
		switch d.Val() {
		case "service":
			if !d.NextArg() {
				return d.ArgErr()
			}
			if u.Service != "" {
				return d.Errf("srv service has already been specified")
			}
			u.Service = d.Val()

		case "proto":
			if !d.NextArg() {
				return d.ArgErr()
			}
			if u.Proto != "" {
				return d.Errf("srv proto has already been specified")
			}
			u.Proto = d.Val()

		case "name":
			if !d.NextArg() {
				return d.ArgErr()
			}
			if u.Name != "" {
				return d.Errf("srv name has already been specified")
			}
			u.Name = d.Val()

		case "refresh":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("parsing refresh interval duration: %v", err)
			}
			u.Refresh = caddy.Duration(dur)

		case "resolvers":
			if u.Resolver == nil {
				u.Resolver = new(UpstreamResolver)
			}
			u.Resolver.Addresses = d.RemainingArgs()
			if len(u.Resolver.Addresses) == 0 {
				return d.Errf("must specify at least one resolver address")
			}

		case "dial_timeout":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("bad timeout value '%s': %v", d.Val(), err)
			}
			u.DialTimeout = caddy.Duration(dur)

		case "dial_fallback_delay":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("bad delay value '%s': %v", d.Val(), err)
			}
			u.FallbackDelay = caddy.Duration(dur)
		case "grace_period":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("bad grace period value '%s': %v", d.Val(), err)
			}
			u.GracePeriod = caddy.Duration(dur)
		default:
			return d.Errf("unrecognized srv option '%s'", d.Val())
		}
	}
	return nil
}

// UnmarshalCaddyfile deserializes Caddyfile tokens into h.
//
//	dynamic a [<name> <port] {
//	    name                <name>
//	    port                <port>
//	    refresh             <interval>
//	    resolvers           <resolvers...>
//	    dial_timeout        <timeout>
//	    dial_fallback_delay <timeout>
//	    versions            ipv4|ipv6
//	}
func (u *AUpstreams) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume upstream source name

	args := d.RemainingArgs()
	if len(args) > 2 {
		return d.ArgErr()
	}
	if len(args) > 0 {
		u.Name = args[0]
		if len(args) == 2 {
			u.Port = args[1]
		}
	}

	for d.NextBlock(0) {
		switch d.Val() {
		case "name":
			if !d.NextArg() {
				return d.ArgErr()
			}
			if u.Name != "" {
				return d.Errf("a name has already been specified")
			}
			u.Name = d.Val()

		case "port":
			if !d.NextArg() {
				return d.ArgErr()
			}
			if u.Port != "" {
				return d.Errf("a port has already been specified")
			}
			u.Port = d.Val()

		case "refresh":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("parsing refresh interval duration: %v", err)
			}
			u.Refresh = caddy.Duration(dur)

		case "resolvers":
			if u.Resolver == nil {
				u.Resolver = new(UpstreamResolver)
			}
			u.Resolver.Addresses = d.RemainingArgs()
			if len(u.Resolver.Addresses) == 0 {
				return d.Errf("must specify at least one resolver address")
			}

		case "dial_timeout":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("bad timeout value '%s': %v", d.Val(), err)
			}
			u.DialTimeout = caddy.Duration(dur)

		case "dial_fallback_delay":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("bad delay value '%s': %v", d.Val(), err)
			}
			u.FallbackDelay = caddy.Duration(dur)

		case "versions":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.Errf("must specify at least one version")
			}

			if u.Versions == nil {
				u.Versions = &IPVersions{}
			}

			trueBool := true
			for _, arg := range args {
				switch arg {
				case "ipv4":
					u.Versions.IPv4 = &trueBool
				case "ipv6":
					u.Versions.IPv6 = &trueBool
				default:
					return d.Errf("unsupported version: '%s'", arg)
				}
			}

		default:
			return d.Errf("unrecognized a option '%s'", d.Val())
		}
	}
	return nil
}

// UnmarshalCaddyfile deserializes Caddyfile tokens into h.
//
//	dynamic multi {
//	    <source> [...]
//	}
func (u *MultiUpstreams) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume upstream source name

	if d.NextArg() {
		return d.ArgErr()
	}

	for d.NextBlock(0) {
		dynModule := d.Val()
		modID := "http.reverse_proxy.upstreams." + dynModule
		unm, err := caddyfile.UnmarshalModule(d, modID)
		if err != nil {
			return err
		}
		source, ok := unm.(UpstreamSource)
		if !ok {
			return d.Errf("module %s (%T) is not an UpstreamSource", modID, unm)
		}
		u.SourcesRaw = append(u.SourcesRaw, caddyconfig.JSONModuleObject(source, "source", dynModule, nil))
	}
	return nil
}

const matcherPrefix = "@"

// Interface guards
var (
	_ caddyfile.Unmarshaler = (*Handler)(nil)
	_ caddyfile.Unmarshaler = (*HTTPTransport)(nil)
	_ caddyfile.Unmarshaler = (*SRVUpstreams)(nil)
	_ caddyfile.Unmarshaler = (*AUpstreams)(nil)
	_ caddyfile.Unmarshaler = (*MultiUpstreams)(nil)
)
