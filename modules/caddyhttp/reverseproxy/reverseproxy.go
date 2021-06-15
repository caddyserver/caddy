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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/headers"
	"go.uber.org/zap"
	"golang.org/x/net/http/httpguts"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler implements a highly configurable and production-ready reverse proxy.
//
// Upon proxying, this module sets the following placeholders (which can be used
// both within and after this handler; for example, in response headers):
//
// Placeholder | Description
// ------------|-------------
// `{http.reverse_proxy.upstream.address}` | The full address to the upstream as given in the config
// `{http.reverse_proxy.upstream.hostport}` | The host:port of the upstream
// `{http.reverse_proxy.upstream.host}` | The host of the upstream
// `{http.reverse_proxy.upstream.port}` | The port of the upstream
// `{http.reverse_proxy.upstream.requests}` | The approximate current number of requests to the upstream
// `{http.reverse_proxy.upstream.max_requests}` | The maximum approximate number of requests allowed to the upstream
// `{http.reverse_proxy.upstream.fails}` | The number of recent failed requests to the upstream
// `{http.reverse_proxy.upstream.latency}` | How long it took the proxy upstream to write the response header.
// `{http.reverse_proxy.upstream.duration}` | Time spent proxying to the upstream, including writing response body to client.
// `{http.reverse_proxy.duration}` | Total time spent proxying, including selecting an upstream, retries, and writing response.
type Handler struct {
	// Configures the method of transport for the proxy. A transport
	// is what performs the actual "round trip" to the backend.
	// The default transport is plaintext HTTP.
	TransportRaw json.RawMessage `json:"transport,omitempty" caddy:"namespace=http.reverse_proxy.transport inline_key=protocol"`

	// A circuit breaker may be used to relieve pressure on a backend
	// that is beginning to exhibit symptoms of stress or latency.
	// By default, there is no circuit breaker.
	CBRaw json.RawMessage `json:"circuit_breaker,omitempty" caddy:"namespace=http.reverse_proxy.circuit_breakers inline_key=type"`

	// Load balancing distributes load/requests between backends.
	LoadBalancing *LoadBalancing `json:"load_balancing,omitempty"`

	// Health checks update the status of backends, whether they are
	// up or down. Down backends will not be proxied to.
	HealthChecks *HealthChecks `json:"health_checks,omitempty"`

	// Upstreams is the list of backends to proxy to.
	Upstreams UpstreamPool `json:"upstreams,omitempty"`

	// Adjusts how often to flush the response buffer. A
	// negative value disables response buffering.
	// TODO: figure out good defaults and write docs for this
	// (see https://github.com/caddyserver/caddy/issues/1460)
	FlushInterval caddy.Duration `json:"flush_interval,omitempty"`

	// Headers manipulates headers between Caddy and the backend.
	// By default, all headers are passed-thru without changes,
	// with the exceptions of special hop-by-hop headers.
	//
	// X-Forwarded-For and X-Forwarded-Proto are also set
	// implicitly, but this may change in the future if the official
	// standardized Forwarded header field gains more adoption.
	Headers *headers.Handler `json:"headers,omitempty"`

	// If true, the entire request body will be read and buffered
	// in memory before being proxied to the backend. This should
	// be avoided if at all possible for performance reasons, but
	// could be useful if the backend is intolerant of read latency.
	BufferRequests bool `json:"buffer_requests,omitempty"`

	// If true, the entire response body will be read and buffered
	// in memory before being proxied to the client. This should
	// be avoided if at all possible for performance reasons, but
	// could be useful if the backend has tighter memory constraints.
	BufferResponses bool `json:"buffer_responses,omitempty"`

	// If body buffering is enabled, the maximum size of the buffers
	// used for the requests and responses (in bytes).
	MaxBufferSize int64 `json:"max_buffer_size,omitempty"`

	// List of handlers and their associated matchers to evaluate
	// after successful roundtrips. The first handler that matches
	// the response from a backend will be invoked. The response
	// body from the backend will not be written to the client;
	// it is up to the handler to finish handling the response.
	// If passive health checks are enabled, any errors from the
	// handler chain will not affect the health status of the
	// backend.
	//
	// Three new placeholders are available in this handler chain:
	// - `{http.reverse_proxy.status_code}` The status code from the response
	// - `{http.reverse_proxy.status_text}` The status text from the response
	// - `{http.reverse_proxy.header.*}` The headers from the response
	HandleResponse []caddyhttp.ResponseHandler `json:"handle_response,omitempty"`

	Transport http.RoundTripper `json:"-"`
	CB        CircuitBreaker    `json:"-"`

	// Holds the named response matchers from the Caddyfile while adapting
	responseMatchers map[string]caddyhttp.ResponseMatcher

	// Holds the handle_response Caddyfile tokens while adapting
	handleResponseSegments []*caddyfile.Dispenser

	ctx    caddy.Context
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.reverse_proxy",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision ensures that h is set up properly before use.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.ctx = ctx
	h.logger = ctx.Logger(h)

	// verify SRV compatibility
	for i, v := range h.Upstreams {
		if v.LookupSRV == "" {
			continue
		}
		if h.HealthChecks != nil && h.HealthChecks.Active != nil {
			return fmt.Errorf(`upstream: lookup_srv is incompatible with active health checks: %d: {"dial": %q, "lookup_srv": %q}`, i, v.Dial, v.LookupSRV)
		}
		if v.Dial != "" {
			return fmt.Errorf(`upstream: specifying dial address is incompatible with lookup_srv: %d: {"dial": %q, "lookup_srv": %q}`, i, v.Dial, v.LookupSRV)
		}
	}

	// start by loading modules
	if h.TransportRaw != nil {
		mod, err := ctx.LoadModule(h, "TransportRaw")
		if err != nil {
			return fmt.Errorf("loading transport: %v", err)
		}
		h.Transport = mod.(http.RoundTripper)
	}
	if h.LoadBalancing != nil && h.LoadBalancing.SelectionPolicyRaw != nil {
		mod, err := ctx.LoadModule(h.LoadBalancing, "SelectionPolicyRaw")
		if err != nil {
			return fmt.Errorf("loading load balancing selection policy: %s", err)
		}
		h.LoadBalancing.SelectionPolicy = mod.(Selector)
	}
	if h.CBRaw != nil {
		mod, err := ctx.LoadModule(h, "CBRaw")
		if err != nil {
			return fmt.Errorf("loading circuit breaker: %s", err)
		}
		h.CB = mod.(CircuitBreaker)
	}

	// ensure any embedded headers handler module gets provisioned
	// (see https://caddy.community/t/set-cookie-manipulation-in-reverse-proxy/7666?u=matt
	// for what happens if we forget to provision it)
	if h.Headers != nil {
		err := h.Headers.Provision(ctx)
		if err != nil {
			return fmt.Errorf("provisioning embedded headers handler: %v", err)
		}
	}

	// set up transport
	if h.Transport == nil {
		t := &HTTPTransport{
			KeepAlive: &KeepAlive{
				ProbeInterval:       caddy.Duration(30 * time.Second),
				IdleConnTimeout:     caddy.Duration(2 * time.Minute),
				MaxIdleConnsPerHost: 32, // seems about optimal, see #2805
			},
			DialTimeout: caddy.Duration(10 * time.Second),
		}
		err := t.Provision(ctx)
		if err != nil {
			return fmt.Errorf("provisioning default transport: %v", err)
		}
		h.Transport = t
	}

	// set up load balancing
	if h.LoadBalancing == nil {
		h.LoadBalancing = new(LoadBalancing)
	}
	if h.LoadBalancing.SelectionPolicy == nil {
		h.LoadBalancing.SelectionPolicy = RandomSelection{}
	}
	if h.LoadBalancing.TryDuration > 0 && h.LoadBalancing.TryInterval == 0 {
		// a non-zero try_duration with a zero try_interval
		// will always spin the CPU for try_duration if the
		// upstream is local or low-latency; avoid that by
		// defaulting to a sane wait period between attempts
		h.LoadBalancing.TryInterval = caddy.Duration(250 * time.Millisecond)
	}
	lbMatcherSets, err := ctx.LoadModule(h.LoadBalancing, "RetryMatchRaw")
	if err != nil {
		return err
	}
	err = h.LoadBalancing.RetryMatch.FromInterface(lbMatcherSets)
	if err != nil {
		return err
	}

	// set up upstreams
	for _, upstream := range h.Upstreams {
		// create or get the host representation for this upstream
		var host Host = new(upstreamHost)
		existingHost, loaded := hosts.LoadOrStore(upstream.String(), host)
		if loaded {
			host = existingHost.(Host)
		}
		upstream.Host = host

		// give it the circuit breaker, if any
		upstream.cb = h.CB

		// if the passive health checker has a non-zero UnhealthyRequestCount
		// but the upstream has no MaxRequests set (they are the same thing,
		// but the passive health checker is a default value for for upstreams
		// without MaxRequests), copy the value into this upstream, since the
		// value in the upstream (MaxRequests) is what is used during
		// availability checks
		if h.HealthChecks != nil && h.HealthChecks.Passive != nil {
			h.HealthChecks.Passive.logger = h.logger.Named("health_checker.passive")
			if h.HealthChecks.Passive.UnhealthyRequestCount > 0 &&
				upstream.MaxRequests == 0 {
				upstream.MaxRequests = h.HealthChecks.Passive.UnhealthyRequestCount
			}
		}

		// upstreams need independent access to the passive
		// health check policy because passive health checks
		// run without access to h.
		if h.HealthChecks != nil {
			upstream.healthCheckPolicy = h.HealthChecks.Passive
		}
	}

	if h.HealthChecks != nil {
		// set defaults on passive health checks, if necessary
		if h.HealthChecks.Passive != nil {
			if h.HealthChecks.Passive.FailDuration > 0 && h.HealthChecks.Passive.MaxFails == 0 {
				h.HealthChecks.Passive.MaxFails = 1
			}
		}

		// if active health checks are enabled, configure them and start a worker
		if h.HealthChecks.Active != nil && (h.HealthChecks.Active.Path != "" ||
			h.HealthChecks.Active.URI != "" ||
			h.HealthChecks.Active.Port != 0) {

			h.HealthChecks.Active.logger = h.logger.Named("health_checker.active")

			timeout := time.Duration(h.HealthChecks.Active.Timeout)
			if timeout == 0 {
				timeout = 5 * time.Second
			}

			if h.HealthChecks.Active.Path != "" {
				h.HealthChecks.Active.logger.Warn("the 'path' option is deprecated, please use 'uri' instead!")
			}

			// parse the URI string (supports path and query)
			if h.HealthChecks.Active.URI != "" {
				parsedURI, err := url.Parse(h.HealthChecks.Active.URI)
				if err != nil {
					return err
				}
				h.HealthChecks.Active.uri = parsedURI
			}

			h.HealthChecks.Active.httpClient = &http.Client{
				Timeout:   timeout,
				Transport: h.Transport,
			}

			for _, upstream := range h.Upstreams {
				// if there's an alternative port for health-check provided in the config,
				// then use it, otherwise use the port of upstream.
				if h.HealthChecks.Active.Port != 0 {
					upstream.activeHealthCheckPort = h.HealthChecks.Active.Port
				}
			}

			if h.HealthChecks.Active.Interval == 0 {
				h.HealthChecks.Active.Interval = caddy.Duration(30 * time.Second)
			}

			if h.HealthChecks.Active.ExpectBody != "" {
				var err error
				h.HealthChecks.Active.bodyRegexp, err = regexp.Compile(h.HealthChecks.Active.ExpectBody)
				if err != nil {
					return fmt.Errorf("expect_body: compiling regular expression: %v", err)
				}
			}

			go h.activeHealthChecker()
		}
	}

	// set up any response routes
	for i, rh := range h.HandleResponse {
		err := rh.Provision(ctx)
		if err != nil {
			return fmt.Errorf("provisioning response handler %d: %v", i, err)
		}
	}

	return nil
}

// Cleanup cleans up the resources made by h during provisioning.
func (h *Handler) Cleanup() error {
	// TODO: Close keepalive connections on reload? https://github.com/caddyserver/caddy/pull/2507/files#diff-70219fd88fe3f36834f474ce6537ed26R762

	// remove hosts from our config from the pool
	for _, upstream := range h.Upstreams {
		_, _ = hosts.Delete(upstream.String())
	}

	return nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	// if enabled, buffer client request;
	// this should only be enabled if the
	// upstream requires it and does not
	// work with "slow clients" (gunicorn,
	// etc.) - this obviously has a perf
	// overhead and makes the proxy at
	// risk of exhausting memory and more
	// susceptible to slowloris attacks,
	// so it is strongly recommended to
	// only use this feature if absolutely
	// required, if read timeouts are set,
	// and if body size is limited
	if h.BufferRequests {
		r.Body = h.bufferedBody(r.Body)
	}

	// prepare the request for proxying; this is needed only once
	err := h.prepareRequest(r)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError,
			fmt.Errorf("preparing request for upstream round-trip: %v", err))
	}

	// we will need the original headers and Host value if
	// header operations are configured; and we should
	// restore them after we're done if they are changed
	// (for example, changing the outbound Host header
	// should not permanently change r.Host; issue #3509)
	reqHost := r.Host
	reqHeader := r.Header
	defer func() {
		r.Host = reqHost     // TODO: data race, see #4038
		r.Header = reqHeader // TODO: data race, see #4038
	}()

	start := time.Now()
	defer func() {
		// total proxying duration, including time spent on LB and retries
		repl.Set("http.reverse_proxy.duration", time.Since(start))
	}()

	var proxyErr error
	for {
		// choose an available upstream
		upstream := h.LoadBalancing.SelectionPolicy.Select(h.Upstreams, r, w)
		if upstream == nil {
			if proxyErr == nil {
				proxyErr = fmt.Errorf("no upstreams available")
			}
			if !h.LoadBalancing.tryAgain(h.ctx, start, proxyErr, r) {
				break
			}
			continue
		}

		// the dial address may vary per-request if placeholders are
		// used, so perform those replacements here; the resulting
		// DialInfo struct should have valid network address syntax
		dialInfo, err := upstream.fillDialInfo(r)
		if err != nil {
			return statusError(fmt.Errorf("making dial info: %v", err))
		}

		// attach to the request information about how to dial the upstream;
		// this is necessary because the information cannot be sufficiently
		// or satisfactorily represented in a URL
		caddyhttp.SetVar(r.Context(), dialInfoVarKey, dialInfo)

		// set placeholders with information about this upstream
		repl.Set("http.reverse_proxy.upstream.address", dialInfo.String())
		repl.Set("http.reverse_proxy.upstream.hostport", dialInfo.Address)
		repl.Set("http.reverse_proxy.upstream.host", dialInfo.Host)
		repl.Set("http.reverse_proxy.upstream.port", dialInfo.Port)
		repl.Set("http.reverse_proxy.upstream.requests", upstream.Host.NumRequests())
		repl.Set("http.reverse_proxy.upstream.max_requests", upstream.MaxRequests)
		repl.Set("http.reverse_proxy.upstream.fails", upstream.Host.Fails())

		// mutate request headers according to this upstream;
		// because we're in a retry loop, we have to copy
		// headers (and the r.Host value) from the original
		// so that each retry is identical to the first
		if h.Headers != nil && h.Headers.Request != nil {
			r.Header = make(http.Header)
			copyHeader(r.Header, reqHeader)
			r.Host = reqHost
			h.Headers.Request.ApplyToRequest(r)
		}

		// proxy the request to that upstream
		proxyErr = h.reverseProxy(w, r, repl, dialInfo, next)
		if proxyErr == nil || proxyErr == context.Canceled {
			// context.Canceled happens when the downstream client
			// cancels the request, which is not our failure
			return nil
		}

		// if the roundtrip was successful, don't retry the request or
		// ding the health status of the upstream (an error can still
		// occur after the roundtrip if, for example, a response handler
		// after the roundtrip returns an error)
		if succ, ok := proxyErr.(roundtripSucceeded); ok {
			return succ.error
		}

		// remember this failure (if enabled)
		h.countFailure(upstream)

		// if we've tried long enough, break
		if !h.LoadBalancing.tryAgain(h.ctx, start, proxyErr, r) {
			break
		}
	}

	return statusError(proxyErr)
}

// prepareRequest modifies req so that it is ready to be proxied,
// except for directing to a specific upstream. This method mutates
// headers and other necessary properties of the request and should
// be done just once (before proxying) regardless of proxy retries.
// This assumes that no mutations of the request are performed
// by h during or after proxying.
func (h Handler) prepareRequest(req *http.Request) error {
	// most of this is borrowed from the Go std lib reverse proxy

	if req.ContentLength == 0 {
		req.Body = nil // Issue golang/go#16036: nil Body for http.Transport retries
	}

	req.Close = false

	// if User-Agent is not set by client, then explicitly
	// disable it so it's not set to default value by std lib
	if _, ok := req.Header["User-Agent"]; !ok {
		req.Header.Set("User-Agent", "")
	}

	reqUpType := upgradeType(req.Header)
	removeConnectionHeaders(req.Header)

	// Remove hop-by-hop headers to the backend. Especially
	// important is "Connection" because we want a persistent
	// connection, regardless of what the client sent to us.
	// Issue golang/go#46313: don't skip if field is empty.
	for _, h := range hopHeaders {
		// Issue golang/go#21096: tell backend applications that care about trailer support
		// that we support trailers. (We do, but we don't go out of our way to
		// advertise that unless the incoming client request thought it was worth
		// mentioning.)
		if h == "Te" && httpguts.HeaderValuesContainsToken(req.Header["Te"], "trailers") {
			req.Header.Set("Te", "trailers")
			continue
		}
		req.Header.Del(h)
	}

	// After stripping all the hop-by-hop connection headers above, add back any
	// necessary for protocol upgrades, such as for websockets.
	if reqUpType != "" {
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", reqUpType)
	}

	if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		// If we aren't the first proxy retain prior
		// X-Forwarded-For information as a comma+space
		// separated list and fold multiple headers into one.
		if prior, ok := req.Header["X-Forwarded-For"]; ok {
			clientIP = strings.Join(prior, ", ") + ", " + clientIP
		}
		req.Header.Set("X-Forwarded-For", clientIP)
	}

	if req.Header.Get("X-Forwarded-Proto") == "" {
		// set X-Forwarded-Proto; many backend apps expect this too
		proto := "https"
		if req.TLS == nil {
			proto = "http"
		}
		req.Header.Set("X-Forwarded-Proto", proto)
	}

	return nil
}

// reverseProxy performs a round-trip to the given backend and processes the response with the client.
// (This method is mostly the beginning of what was borrowed from the net/http/httputil package in the
// Go standard library which was used as the foundation.)
func (h *Handler) reverseProxy(rw http.ResponseWriter, req *http.Request, repl *caddy.Replacer, di DialInfo, next caddyhttp.Handler) error {
	_ = di.Upstream.Host.CountRequest(1)
	//nolint:errcheck
	defer di.Upstream.Host.CountRequest(-1)

	// point the request to this upstream
	h.directRequest(req, di)

	// do the round-trip; emit debug log with values we know are
	// safe, or if there is no error, emit fuller log entry
	start := time.Now()
	res, err := h.Transport.RoundTrip(req)
	duration := time.Since(start)
	logger := h.logger.With(
		zap.String("upstream", di.Upstream.String()),
		zap.Object("request", caddyhttp.LoggableHTTPRequest{Request: req}),
	)
	if err != nil {
		logger.Debug("upstream roundtrip",
			zap.Duration("duration", duration),
			zap.Error(err))
		return err
	}
	logger.Debug("upstream roundtrip",
		zap.Object("headers", caddyhttp.LoggableHTTPHeader(res.Header)),
		zap.Int("status", res.StatusCode))

	// duration until upstream wrote response headers (roundtrip duration)
	repl.Set("http.reverse_proxy.upstream.latency", duration)

	// update circuit breaker on current conditions
	if di.Upstream.cb != nil {
		di.Upstream.cb.RecordMetric(res.StatusCode, duration)
	}

	// perform passive health checks (if enabled)
	if h.HealthChecks != nil && h.HealthChecks.Passive != nil {
		// strike if the status code matches one that is "bad"
		for _, badStatus := range h.HealthChecks.Passive.UnhealthyStatus {
			if caddyhttp.StatusCodeMatches(res.StatusCode, badStatus) {
				h.countFailure(di.Upstream)
			}
		}

		// strike if the roundtrip took too long
		if h.HealthChecks.Passive.UnhealthyLatency > 0 &&
			duration >= time.Duration(h.HealthChecks.Passive.UnhealthyLatency) {
			h.countFailure(di.Upstream)
		}
	}

	// if enabled, buffer the response body
	if h.BufferResponses {
		res.Body = h.bufferedBody(res.Body)
	}

	// see if any response handler is configured for this response from the backend
	for i, rh := range h.HandleResponse {
		if rh.Match != nil && !rh.Match.Match(res.StatusCode, res.Header) {
			continue
		}

		// if configured to only change the status code, do that then continue regular proxy response
		if statusCodeStr := rh.StatusCode.String(); statusCodeStr != "" {
			statusCode, err := strconv.Atoi(repl.ReplaceAll(statusCodeStr, ""))
			if err != nil {
				return caddyhttp.Error(http.StatusInternalServerError, err)
			}
			if statusCode != 0 {
				res.StatusCode = statusCode
			}
			break
		}

		// otherwise, if there are any routes configured, execute those as the
		// actual response instead of what we got from the proxy backend
		if len(rh.Routes) == 0 {
			continue
		}

		res.Body.Close()

		// set up the replacer so that parts of the original response can be
		// used for routing decisions
		for field, value := range res.Header {
			repl.Set("http.reverse_proxy.header."+field, strings.Join(value, ","))
		}
		repl.Set("http.reverse_proxy.status_code", res.StatusCode)
		repl.Set("http.reverse_proxy.status_text", res.Status)

		h.logger.Debug("handling response", zap.Int("handler", i))
		if routeErr := rh.Routes.Compile(next).ServeHTTP(rw, req); routeErr != nil {
			// wrap error in roundtripSucceeded so caller knows that
			// the roundtrip was successful and to not retry
			return roundtripSucceeded{routeErr}
		}
	}

	// deal with 101 Switching Protocols responses: (WebSocket, h2c, etc)
	if res.StatusCode == http.StatusSwitchingProtocols {
		h.handleUpgradeResponse(logger, rw, req, res)
		return nil
	}

	removeConnectionHeaders(res.Header)

	for _, h := range hopHeaders {
		res.Header.Del(h)
	}

	// apply any response header operations
	if h.Headers != nil && h.Headers.Response != nil {
		if h.Headers.Response.Require == nil ||
			h.Headers.Response.Require.Match(res.StatusCode, res.Header) {
			h.Headers.Response.ApplyTo(res.Header, repl)
		}
	}

	copyHeader(rw.Header(), res.Header)

	// The "Trailer" header isn't included in the Transport's response,
	// at least for *http.Transport. Build it up from Trailer.
	announcedTrailers := len(res.Trailer)
	if announcedTrailers > 0 {
		trailerKeys := make([]string, 0, len(res.Trailer))
		for k := range res.Trailer {
			trailerKeys = append(trailerKeys, k)
		}
		rw.Header().Add("Trailer", strings.Join(trailerKeys, ", "))
	}

	rw.WriteHeader(res.StatusCode)

	// some apps need the response headers before starting to stream content with http2,
	// so it's important to explicitly flush the headers to the client before streaming the data.
	// (see https://github.com/caddyserver/caddy/issues/3556 for use case and nuances)
	if h.isBidirectionalStream(req, res) {
		if wf, ok := rw.(http.Flusher); ok {
			wf.Flush()
		}
	}
	err = h.copyResponse(rw, res.Body, h.flushInterval(req, res))
	res.Body.Close() // close now, instead of defer, to populate res.Trailer
	if err != nil {
		// we're streaming the response and we've already written headers, so
		// there's nothing an error handler can do to recover at this point;
		// the standard lib's proxy panics at this point, but we'll just log
		// the error and abort the stream here
		h.logger.Error("aborting with incomplete response", zap.Error(err))
		return nil
	}

	if len(res.Trailer) > 0 {
		// Force chunking if we saw a response trailer.
		// This prevents net/http from calculating the length for short
		// bodies and adding a Content-Length.
		if fl, ok := rw.(http.Flusher); ok {
			fl.Flush()
		}
	}

	// total duration spent proxying, including writing response body
	repl.Set("http.reverse_proxy.upstream.duration", duration)

	if len(res.Trailer) == announcedTrailers {
		copyHeader(rw.Header(), res.Trailer)
		return nil
	}

	for k, vv := range res.Trailer {
		k = http.TrailerPrefix + k
		for _, v := range vv {
			rw.Header().Add(k, v)
		}
	}

	return nil
}

// tryAgain takes the time that the handler was initially invoked
// as well as any error currently obtained, and the request being
// tried, and returns true if another attempt should be made at
// proxying the request. If true is returned, it has already blocked
// long enough before the next retry (i.e. no more sleeping is
// needed). If false is returned, the handler should stop trying to
// proxy the request.
func (lb LoadBalancing) tryAgain(ctx caddy.Context, start time.Time, proxyErr error, req *http.Request) bool {
	// if we've tried long enough, break
	if time.Since(start) >= time.Duration(lb.TryDuration) {
		return false
	}

	// if the error occurred while dialing (i.e. a connection
	// could not even be established to the upstream), then it
	// should be safe to retry, since without a connection, no
	// HTTP request can be transmitted; but if the error is not
	// specifically a dialer error, we need to be careful
	if _, ok := proxyErr.(DialError); proxyErr != nil && !ok {
		// if the error occurred after a connection was established,
		// we have to assume the upstream received the request, and
		// retries need to be carefully decided, because some requests
		// are not idempotent
		if lb.RetryMatch == nil && req.Method != "GET" {
			// by default, don't retry requests if they aren't GET
			return false
		}
		if !lb.RetryMatch.AnyMatch(req) {
			return false
		}
	}

	// otherwise, wait and try the next available host
	select {
	case <-time.After(time.Duration(lb.TryInterval)):
		return true
	case <-ctx.Done():
		return false
	}
}

// directRequest modifies only req.URL so that it points to the upstream
// in the given DialInfo. It must modify ONLY the request URL.
func (h Handler) directRequest(req *http.Request, di DialInfo) {
	// we need a host, so set the upstream's host address
	reqHost := di.Address

	// if the port equates to the scheme, strip the port because
	// it's weird to make a request like http://example.com:80/.
	if (req.URL.Scheme == "http" && di.Port == "80") ||
		(req.URL.Scheme == "https" && di.Port == "443") {
		reqHost = di.Host
	}

	req.URL.Host = reqHost
}

// bufferedBody reads originalBody into a buffer, then returns a reader for the buffer.
// Always close the return value when done with it, just like if it was the original body!
func (h Handler) bufferedBody(originalBody io.ReadCloser) io.ReadCloser {
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	if h.MaxBufferSize > 0 {
		n, err := io.CopyN(buf, originalBody, h.MaxBufferSize)
		if err != nil || n == h.MaxBufferSize {
			return bodyReadCloser{
				Reader: io.MultiReader(buf, originalBody),
				buf:    buf,
				body:   originalBody,
			}
		}
	} else {
		_, _ = io.Copy(buf, originalBody)
	}
	originalBody.Close() // no point in keeping it open
	return bodyReadCloser{
		Reader: buf,
		buf:    buf,
	}
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func upgradeType(h http.Header) string {
	if !httpguts.HeaderValuesContainsToken(h["Connection"], "Upgrade") {
		return ""
	}
	return strings.ToLower(h.Get("Upgrade"))
}

// removeConnectionHeaders removes hop-by-hop headers listed in the "Connection" header of h.
// See RFC 7230, section 6.1
func removeConnectionHeaders(h http.Header) {
	if c := h.Get("Connection"); c != "" {
		for _, f := range strings.Split(c, ",") {
			if f = strings.TrimSpace(f); f != "" {
				h.Del(f)
			}
		}
	}
}

// statusError returns an error value that has a status code.
func statusError(err error) error {
	// errors proxying usually mean there is a problem with the upstream(s)
	statusCode := http.StatusBadGateway

	// if the client canceled the request (usually this means they closed
	// the connection, so they won't see any response), we can report it
	// as a client error (4xx) and not a server error (5xx); unfortunately
	// the Go standard library, at least at time of writing in late 2020,
	// obnoxiously wraps the exported, standard context.Canceled error with
	// an unexported garbage value that we have to do a substring check for:
	// https://github.com/golang/go/blob/6965b01ea248cabb70c3749fd218b36089a21efb/src/net/net.go#L416-L430
	if errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "operation was canceled") {
		// regrettably, there is no standard error code for "client closed connection", but
		// for historical reasons we can use a code that a lot of people are already using;
		// using 5xx is problematic for users; see #3748
		statusCode = 499
	}
	return caddyhttp.Error(statusCode, err)
}

// LoadBalancing has parameters related to load balancing.
type LoadBalancing struct {
	// A selection policy is how to choose an available backend.
	// The default policy is random selection.
	SelectionPolicyRaw json.RawMessage `json:"selection_policy,omitempty" caddy:"namespace=http.reverse_proxy.selection_policies inline_key=policy"`

	// How long to try selecting available backends for each request
	// if the next available host is down. By default, this retry is
	// disabled. Clients will wait for up to this long while the load
	// balancer tries to find an available upstream host.
	TryDuration caddy.Duration `json:"try_duration,omitempty"`

	// How long to wait between selecting the next host from the pool. Default
	// is 250ms. Only relevant when a request to an upstream host fails. Be
	// aware that setting this to 0 with a non-zero try_duration can cause the
	// CPU to spin if all backends are down and latency is very low.
	TryInterval caddy.Duration `json:"try_interval,omitempty"`

	// A list of matcher sets that restricts with which requests retries are
	// allowed. A request must match any of the given matcher sets in order
	// to be retried if the connection to the upstream succeeded but the
	// subsequent round-trip failed. If the connection to the upstream failed,
	// a retry is always allowed. If unspecified, only GET requests will be
	// allowed to be retried. Note that a retry is done with the next available
	// host according to the load balancing policy.
	RetryMatchRaw caddyhttp.RawMatcherSets `json:"retry_match,omitempty" caddy:"namespace=http.matchers"`

	SelectionPolicy Selector              `json:"-"`
	RetryMatch      caddyhttp.MatcherSets `json:"-"`
}

// Selector selects an available upstream from the pool.
type Selector interface {
	Select(UpstreamPool, *http.Request, http.ResponseWriter) *Upstream
}

// Hop-by-hop headers. These are removed when sent to the backend.
// As of RFC 7230, hop-by-hop headers are required to appear in the
// Connection header field. These are the headers defined by the
// obsoleted RFC 2616 (section 13.5.1) and are used for backward
// compatibility.
var hopHeaders = []string{
	"Alt-Svc",
	"Connection",
	"Proxy-Connection", // non-standard but still sent by libcurl and rejected by e.g. google
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",      // canonicalized version of "TE"
	"Trailer", // not Trailers per URL above; https://www.rfc-editor.org/errata_search.php?eid=4522
	"Transfer-Encoding",
	"Upgrade",
}

// DialError is an error that specifically occurs
// in a call to Dial or DialContext.
type DialError struct{ error }

// TLSTransport is implemented by transports
// that are capable of using TLS.
type TLSTransport interface {
	// TLSEnabled returns true if the transport
	// has TLS enabled, false otherwise.
	TLSEnabled() bool

	// EnableTLS enables TLS within the transport
	// if it is not already, using the provided
	// value as a basis for the TLS config.
	EnableTLS(base *TLSConfig) error
}

// roundtripSucceeded is an error type that is returned if the
// roundtrip succeeded, but an error occurred after-the-fact.
type roundtripSucceeded struct{ error }

// bodyReadCloser is a reader that, upon closing, will return
// its buffer to the pool and close the underlying body reader.
type bodyReadCloser struct {
	io.Reader
	buf  *bytes.Buffer
	body io.ReadCloser
}

func (brc bodyReadCloser) Close() error {
	bufPool.Put(brc.buf)
	if brc.body != nil {
		return brc.body.Close()
	}
	return nil
}

// bufPool is used for buffering requests and responses.
var bufPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.CleanerUpper          = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)
