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
	"log"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"

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
	err = rp.FinalizeUnmarshalCaddyfile(h)
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
//         health_headers {
//             <field> [<values...>]
//         }
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
//         buffer_requests
//
//         # header manipulation
//         header_up   [+|-]<field> [<value|regexp> [<replacement>]]
//         header_down [+|-]<field> [<value|regexp> [<replacement>]]
//
//         # round trip
//         transport <name> {
//             ...
//         }
//
//         # handle responses
//         @name {
//             status <code...>
//             header <field> [<value>]
//         }
//         handle_response [<matcher>] [status_code] {
//             <directives...>
//         }
//     }
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

	// TODO: the logic in this function is kind of sensitive, we need
	// to write tests before making any more changes to it
	upstreamDialAddress := func(upstreamAddr string) (string, error) {
		var network, scheme, host, port string

		if strings.Contains(upstreamAddr, "://") {
			// we get a parsing error if a placeholder is specified
			// so we return a more user-friendly error message instead
			// to explain what to do instead
			if strings.Contains(upstreamAddr, "{") {
				return "", d.Err("due to parsing difficulties, placeholders are not allowed when an upstream address contains a scheme")
			}

			toURL, err := url.Parse(upstreamAddr)
			if err != nil {
				return "", d.Errf("parsing upstream URL: %v", err)
			}

			// there is currently no way to perform a URL rewrite between choosing
			// a backend and proxying to it, so we cannot allow extra components
			// in backend URLs
			if toURL.Path != "" || toURL.RawQuery != "" || toURL.Fragment != "" {
				return "", d.Err("for now, URLs for proxy upstreams only support scheme, host, and port components")
			}

			// ensure the port and scheme aren't in conflict
			urlPort := toURL.Port()
			if toURL.Scheme == "http" && urlPort == "443" {
				return "", d.Err("upstream address has conflicting scheme (http://) and port (:443, the HTTPS port)")
			}
			if toURL.Scheme == "https" && urlPort == "80" {
				return "", d.Err("upstream address has conflicting scheme (https://) and port (:80, the HTTP port)")
			}
			if toURL.Scheme == "h2c" && urlPort == "443" {
				return "", d.Err("upstream address has conflicting scheme (h2c://) and port (:443, the HTTPS port)")
			}

			// if port is missing, attempt to infer from scheme
			if toURL.Port() == "" {
				var toPort string
				switch toURL.Scheme {
				case "", "http", "h2c":
					toPort = "80"
				case "https":
					toPort = "443"
				}
				toURL.Host = net.JoinHostPort(toURL.Hostname(), toPort)
			}

			scheme, host, port = toURL.Scheme, toURL.Hostname(), toURL.Port()
		} else {
			// extract network manually, since caddy.ParseNetworkAddress() will always add one
			if idx := strings.Index(upstreamAddr, "/"); idx >= 0 {
				network = strings.ToLower(strings.TrimSpace(upstreamAddr[:idx]))
				upstreamAddr = upstreamAddr[idx+1:]
			}
			var err error
			host, port, err = net.SplitHostPort(upstreamAddr)
			if err != nil {
				host = upstreamAddr
			}
			// we can assume a port if only a hostname is specified, but use of a
			// placeholder without a port likely means a port will be filled in
			if port == "" && !strings.Contains(host, "{") {
				port = "80"
			}
		}

		// the underlying JSON does not yet support different
		// transports (protocols or schemes) to each backend,
		// so we remember the last one we see and compare them
		if commonScheme != "" && scheme != commonScheme {
			return "", d.Errf("for now, all proxy upstreams must use the same scheme (transport protocol); expecting '%s://' but got '%s://'",
				commonScheme, scheme)
		}
		commonScheme = scheme

		// for simplest possible config, we only need to include
		// the network portion if the user specified one
		if network != "" {
			return caddy.JoinNetworkAddress(network, host, port), nil
		}

		// if the host is a placeholder, then we don't want to join with an empty port,
		// because that would just append an extra ':' at the end of the address.
		if port == "" && strings.Contains(host, "{") {
			return host, nil
		}

		return net.JoinHostPort(host, port), nil
	}

	// appendUpstream creates an upstream for address and adds
	// it to the list. If the address starts with "srv+" it is
	// treated as a SRV-based upstream, and any port will be
	// dropped.
	appendUpstream := func(address string) error {
		isSRV := strings.HasPrefix(address, "srv+")
		if isSRV {
			address = strings.TrimPrefix(address, "srv+")
		}
		dialAddr, err := upstreamDialAddress(address)
		if err != nil {
			return err
		}
		if isSRV {
			if host, _, err := net.SplitHostPort(dialAddr); err == nil {
				dialAddr = host
			}
			h.Upstreams = append(h.Upstreams, &Upstream{LookupSRV: dialAddr})
		} else {
			h.Upstreams = append(h.Upstreams, &Upstream{Dial: dialAddr})
		}
		return nil
	}

	for d.Next() {
		for _, up := range d.RemainingArgs() {
			err := appendUpstream(up)
			if err != nil {
				return err
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
						return err
					}
				}

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

			case "health_headers":
				healthHeaders := make(http.Header)
				for d.Next() {
					for d.NextBlock(0) {
						key := d.Val()
						values := d.RemainingArgs()
						if len(values) == 0 {
							values = append(values, "")
						}
						healthHeaders[key] = values
					}
				}
				if h.HealthChecks == nil {
					h.HealthChecks = new(HealthChecks)
				}
				if h.HealthChecks.Active == nil {
					h.HealthChecks.Active = new(ActiveHealthChecks)
				}
				h.HealthChecks.Active.Headers = healthHeaders

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

			case "buffer_requests":
				if d.NextArg() {
					return d.ArgErr()
				}
				h.BufferRequests = true

			case "buffer_responses":
				if d.NextArg() {
					return d.ArgErr()
				}
				h.BufferResponses = true

			case "max_buffer_size":
				if !d.NextArg() {
					return d.ArgErr()
				}
				size, err := strconv.Atoi(d.Val())
				if err != nil {
					return d.Errf("invalid size (bytes): %s", d.Val())
				}
				if d.NextArg() {
					return d.ArgErr()
				}
				h.MaxBufferSize = int64(size)

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
					err = headers.CaddyfileHeaderOp(h.Headers.Request, args[0], "", "")
				case 2:
					// some lint checks, I guess
					if strings.EqualFold(args[0], "host") && (args[1] == "{hostport}" || args[1] == "{http.request.hostport}") {
						log.Printf("[WARNING] Unnecessary header_up ('Host' field): the reverse proxy's default behavior is to pass headers to the upstream")
					}
					if strings.EqualFold(args[0], "x-forwarded-proto") && (args[1] == "{scheme}" || args[1] == "{http.request.scheme}") {
						log.Printf("[WARNING] Unnecessary header_up ('X-Forwarded-Proto' field): the reverse proxy's default behavior is to pass headers to the upstream")
					}
					err = headers.CaddyfileHeaderOp(h.Headers.Request, args[0], args[1], "")
				case 3:
					err = headers.CaddyfileHeaderOp(h.Headers.Request, args[0], args[1], args[2])
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
					err = headers.CaddyfileHeaderOp(h.Headers.Response.HeaderOps, args[0], "", "")
				case 2:
					err = headers.CaddyfileHeaderOp(h.Headers.Response.HeaderOps, args[0], args[1], "")
				case 3:
					err = headers.CaddyfileHeaderOp(h.Headers.Response.HeaderOps, args[0], args[1], args[2])
				default:
					return d.ArgErr()
				}

				if err != nil {
					return d.Err(err.Error())
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

			default:
				return d.Errf("unrecognized subdirective %s", d.Val())
			}
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

		var matcher *caddyhttp.ResponseMatcher
		args := d.RemainingArgs()

		// the first arg should be a matcher (optional)
		// the second arg should be a status code (optional)
		// any more than that isn't currently supported
		if len(args) > 2 {
			return d.Errf("too many arguments for 'handle_response': %s", args)
		}

		// the first arg should always be a matcher.
		// it doesn't really make sense to support status code without a matcher.
		if len(args) > 0 {
			if !strings.HasPrefix(args[0], matcherPrefix) {
				return d.Errf("must use a named response matcher, starting with '@'")
			}

			foundMatcher, ok := h.responseMatchers[args[0]]
			if !ok {
				return d.Errf("no named response matcher defined with name '%s'", args[0][1:])
			}
			matcher = &foundMatcher
		}

		// a second arg should be a status code, in which case
		// we skip parsing the block for routes
		if len(args) == 2 {
			_, err := strconv.Atoi(args[1])
			if err != nil {
				return d.Errf("bad integer value '%s': %v", args[1], err)
			}

			// make sure there's no block, cause it doesn't make sense
			if d.NextBlock(1) {
				return d.Errf("cannot define routes for 'handle_response' when changing the status code")
			}

			h.HandleResponse = append(
				h.HandleResponse,
				caddyhttp.ResponseHandler{
					Match:      matcher,
					StatusCode: caddyhttp.WeakString(args[1]),
				},
			)
			continue
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
//     transport http {
//         read_buffer             <size>
//         write_buffer            <size>
//         max_response_header     <size>
//         dial_timeout            <duration>
//         dial_fallback_delay     <duration>
//         response_header_timeout <duration>
//         expect_continue_timeout <duration>
//         tls
//         tls_client_auth <automate_name> | <cert_file> <key_file>
//         tls_insecure_skip_verify
//         tls_timeout <duration>
//         tls_trusted_ca_certs <cert_files...>
//         tls_server_name <sni>
//         keepalive [off|<duration>]
//         keepalive_idle_conns <max_count>
//         versions <versions...>
//         compression off
//         max_conns_per_host <count>
//         max_idle_conns_per_host <count>
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

			case "max_response_header":
				if !d.NextArg() {
					return d.ArgErr()
				}
				size, err := humanize.ParseBytes(d.Val())
				if err != nil {
					return d.Errf("invalid max response header size '%s': %v", d.Val(), err)
				}
				h.MaxResponseHeaderSize = int64(size)

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
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("bad timeout value '%s': %v", d.Val(), err)
				}
				if h.TLS == nil {
					h.TLS = new(TLSConfig)
				}
				h.TLS.HandshakeTimeout = caddy.Duration(dur)

			case "tls_trusted_ca_certs":
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}
				if h.TLS == nil {
					h.TLS = new(TLSConfig)
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

			default:
				return d.Errf("unrecognized subdirective %s", d.Val())
			}
		}
	}
	return nil
}

const matcherPrefix = "@"

// Interface guards
var (
	_ caddyfile.Unmarshaler = (*Handler)(nil)
	_ caddyfile.Unmarshaler = (*HTTPTransport)(nil)
)
