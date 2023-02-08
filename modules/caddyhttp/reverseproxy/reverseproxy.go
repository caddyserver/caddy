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
	"net/http/httptrace"
	"net/netip"
	"net/textproto"
	"net/url"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyevents"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/headers"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/rewrite"
	"go.uber.org/zap"
	"golang.org/x/net/http/httpguts"
)

var supports1xx bool

func init() {
	// Caddy requires at least Go 1.18, but Early Hints requires Go 1.19; thus we can simply check for 1.18 in version string
	// TODO: remove this once our minimum Go version is 1.19
	supports1xx = !strings.Contains(runtime.Version(), "go1.18")

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
// `{http.reverse_proxy.upstream.latency_ms}` | Same as 'latency', but in milliseconds.
// `{http.reverse_proxy.upstream.duration}` | Time spent proxying to the upstream, including writing response body to client.
// `{http.reverse_proxy.upstream.duration_ms}` | Same as 'upstream.duration', but in milliseconds.
// `{http.reverse_proxy.duration}` | Total time spent proxying, including selecting an upstream, retries, and writing response.
// `{http.reverse_proxy.duration_ms}` | Same as 'duration', but in milliseconds.
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

	// Upstreams is the static list of backends to proxy to.
	Upstreams UpstreamPool `json:"upstreams,omitempty"`

	// A module for retrieving the list of upstreams dynamically. Dynamic
	// upstreams are retrieved at every iteration of the proxy loop for
	// each request (i.e. before every proxy attempt within every request).
	// Active health checks do not work on dynamic upstreams, and passive
	// health checks are only effective on dynamic upstreams if the proxy
	// server is busy enough that concurrent requests to the same backends
	// are continuous. Instead of health checks for dynamic upstreams, it
	// is recommended that the dynamic upstream module only return available
	// backends in the first place.
	DynamicUpstreamsRaw json.RawMessage `json:"dynamic_upstreams,omitempty" caddy:"namespace=http.reverse_proxy.upstreams inline_key=source"`

	// Adjusts how often to flush the response buffer. By default,
	// no periodic flushing is done. A negative value disables
	// response buffering, and flushes immediately after each
	// write to the client. This option is ignored when the upstream's
	// response is recognized as a streaming response, or if its
	// content length is -1; for such responses, writes are flushed
	// to the client immediately.
	//
	// Normally, a request will be canceled if the client disconnects
	// before the response is received from the backend. If explicitly
	// set to -1, client disconnection will be ignored and the request
	// will be completed to help facilitate low-latency streaming.
	FlushInterval caddy.Duration `json:"flush_interval,omitempty"`

	// A list of IP ranges (supports CIDR notation) from which
	// X-Forwarded-* header values should be trusted. By default,
	// no proxies are trusted, so existing values will be ignored
	// when setting these headers. If the proxy is trusted, then
	// existing values will be used when constructing the final
	// header values.
	TrustedProxies []string `json:"trusted_proxies,omitempty"`

	// Headers manipulates headers between Caddy and the backend.
	// By default, all headers are passed-thru without changes,
	// with the exceptions of special hop-by-hop headers.
	//
	// X-Forwarded-For, X-Forwarded-Proto and X-Forwarded-Host
	// are also set implicitly.
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

	// If configured, rewrites the copy of the upstream request.
	// Allows changing the request method and URI (path and query).
	// Since the rewrite is applied to the copy, it does not persist
	// past the reverse proxy handler.
	// If the method is changed to `GET` or `HEAD`, the request body
	// will not be copied to the backend. This allows a later request
	// handler -- either in a `handle_response` route, or after -- to
	// read the body.
	// By default, no rewrite is performed, and the method and URI
	// from the incoming request is used as-is for proxying.
	Rewrite *rewrite.Rewrite `json:"rewrite,omitempty"`

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

	Transport        http.RoundTripper `json:"-"`
	CB               CircuitBreaker    `json:"-"`
	DynamicUpstreams UpstreamSource    `json:"-"`

	// Holds the parsed CIDR ranges from TrustedProxies
	trustedProxies []netip.Prefix

	// Holds the named response matchers from the Caddyfile while adapting
	responseMatchers map[string]caddyhttp.ResponseMatcher

	// Holds the handle_response Caddyfile tokens while adapting
	handleResponseSegments []*caddyfile.Dispenser

	// Stores upgraded requests (hijacked connections) for proper cleanup
	connections   map[io.ReadWriteCloser]openConnection
	connectionsMu *sync.Mutex

	ctx    caddy.Context
	logger *zap.Logger
	events *caddyevents.App
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
	eventAppIface, err := ctx.App("events")
	if err != nil {
		return fmt.Errorf("getting events app: %v", err)
	}
	h.events = eventAppIface.(*caddyevents.App)
	h.ctx = ctx
	h.logger = ctx.Logger()
	h.connections = make(map[io.ReadWriteCloser]openConnection)
	h.connectionsMu = new(sync.Mutex)

	// verify SRV compatibility - TODO: LookupSRV deprecated; will be removed
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
	if h.DynamicUpstreamsRaw != nil {
		mod, err := ctx.LoadModule(h, "DynamicUpstreamsRaw")
		if err != nil {
			return fmt.Errorf("loading upstream source module: %v", err)
		}
		h.DynamicUpstreams = mod.(UpstreamSource)
	}

	// parse trusted proxy CIDRs ahead of time
	for _, str := range h.TrustedProxies {
		if strings.Contains(str, "/") {
			ipNet, err := netip.ParsePrefix(str)
			if err != nil {
				return fmt.Errorf("parsing CIDR expression: '%s': %v", str, err)
			}
			h.trustedProxies = append(h.trustedProxies, ipNet)
		} else {
			ipAddr, err := netip.ParseAddr(str)
			if err != nil {
				return fmt.Errorf("invalid IP address: '%s': %v", str, err)
			}
			ipNew := netip.PrefixFrom(ipAddr, ipAddr.BitLen())
			h.trustedProxies = append(h.trustedProxies, ipNew)
		}
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

	if h.Rewrite != nil {
		err := h.Rewrite.Provision(ctx)
		if err != nil {
			return fmt.Errorf("provisioning rewrite: %v", err)
		}
	}

	// set up transport
	if h.Transport == nil {
		t := &HTTPTransport{}
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
	for _, u := range h.Upstreams {
		h.provisionUpstream(u)
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

	upstreamHealthyUpdater := newMetricsUpstreamsHealthyUpdater(h)
	upstreamHealthyUpdater.Init()

	return nil
}

// Cleanup cleans up the resources made by h.
func (h *Handler) Cleanup() error {
	// close hijacked connections (both to client and backend)
	var err error
	h.connectionsMu.Lock()
	for _, oc := range h.connections {
		if oc.gracefulClose != nil {
			// this is potentially blocking while we have the lock on the connections
			// map, but that should be OK since the server has in theory shut down
			// and we are no longer using the connections map
			gracefulErr := oc.gracefulClose()
			if gracefulErr != nil && err == nil {
				err = gracefulErr
			}
		}
		closeErr := oc.conn.Close()
		if closeErr != nil && err == nil {
			err = closeErr
		}
	}
	h.connectionsMu.Unlock()

	// remove hosts from our config from the pool
	for _, upstream := range h.Upstreams {
		_, _ = hosts.Delete(upstream.String())
	}

	return err
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	// prepare the request for proxying; this is needed only once
	clonedReq, err := h.prepareRequest(r, repl)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError,
			fmt.Errorf("preparing request for upstream round-trip: %v", err))
	}

	// we will need the original headers and Host value if
	// header operations are configured; this is so that each
	// retry can apply the modifications, because placeholders
	// may be used which depend on the selected upstream for
	// their values
	reqHost := clonedReq.Host
	reqHeader := clonedReq.Header

	start := time.Now()
	defer func() {
		// total proxying duration, including time spent on LB and retries
		repl.Set("http.reverse_proxy.duration", time.Since(start))
		repl.Set("http.reverse_proxy.duration_ms", time.Since(start).Seconds()*1e3) // multiply seconds to preserve decimal (see #4666)
	}()

	// in the proxy loop, each iteration is an attempt to proxy the request,
	// and because we may retry some number of times, carry over the error
	// from previous tries because of the nuances of load balancing & retries
	var proxyErr error
	var retries int
	for {
		var done bool
		done, proxyErr = h.proxyLoopIteration(clonedReq, r, w, proxyErr, start, retries, repl, reqHeader, reqHost, next)
		if done {
			break
		}
		retries++
	}

	if proxyErr != nil {
		return statusError(proxyErr)
	}

	return nil
}

// proxyLoopIteration implements an iteration of the proxy loop. Despite the enormous amount of local state
// that has to be passed in, we brought this into its own method so that we could run defer more easily.
// It returns true when the loop is done and should break; false otherwise. The error value returned should
// be assigned to the proxyErr value for the next iteration of the loop (or the error handled after break).
func (h *Handler) proxyLoopIteration(r *http.Request, origReq *http.Request, w http.ResponseWriter, proxyErr error, start time.Time, retries int,
	repl *caddy.Replacer, reqHeader http.Header, reqHost string, next caddyhttp.Handler) (bool, error) {
	// get the updated list of upstreams
	upstreams := h.Upstreams
	if h.DynamicUpstreams != nil {
		dUpstreams, err := h.DynamicUpstreams.GetUpstreams(r)
		if err != nil {
			h.logger.Error("failed getting dynamic upstreams; falling back to static upstreams", zap.Error(err))
		} else {
			upstreams = dUpstreams
			for _, dUp := range dUpstreams {
				h.provisionUpstream(dUp)
			}
			h.logger.Debug("provisioned dynamic upstreams", zap.Int("count", len(dUpstreams)))
			defer func() {
				// these upstreams are dynamic, so they are only used for this iteration
				// of the proxy loop; be sure to let them go away when we're done with them
				for _, upstream := range dUpstreams {
					_, _ = hosts.Delete(upstream.String())
				}
			}()
		}
	}

	// choose an available upstream
	upstream := h.LoadBalancing.SelectionPolicy.Select(upstreams, r, w)
	if upstream == nil {
		if proxyErr == nil {
			proxyErr = caddyhttp.Error(http.StatusServiceUnavailable, fmt.Errorf("no upstreams available"))
		}
		if !h.LoadBalancing.tryAgain(h.ctx, start, retries, proxyErr, r) {
			return true, proxyErr
		}
		return false, proxyErr
	}

	// the dial address may vary per-request if placeholders are
	// used, so perform those replacements here; the resulting
	// DialInfo struct should have valid network address syntax
	dialInfo, err := upstream.fillDialInfo(r)
	if err != nil {
		return true, fmt.Errorf("making dial info: %v", err)
	}

	h.logger.Debug("selected upstream",
		zap.String("dial", dialInfo.Address),
		zap.Int("total_upstreams", len(upstreams)))

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
	proxyErr = h.reverseProxy(w, r, origReq, repl, dialInfo, next)
	if proxyErr == nil || errors.Is(proxyErr, context.Canceled) {
		// context.Canceled happens when the downstream client
		// cancels the request, which is not our failure
		return true, nil
	}

	// if the roundtrip was successful, don't retry the request or
	// ding the health status of the upstream (an error can still
	// occur after the roundtrip if, for example, a response handler
	// after the roundtrip returns an error)
	if succ, ok := proxyErr.(roundtripSucceeded); ok {
		return true, succ.error
	}

	// remember this failure (if enabled)
	h.countFailure(upstream)

	// if we've tried long enough, break
	if !h.LoadBalancing.tryAgain(h.ctx, start, retries, proxyErr, r) {
		return true, proxyErr
	}

	return false, proxyErr
}

// prepareRequest clones req so that it can be safely modified without
// changing the original request or introducing data races. It then
// modifies it so that it is ready to be proxied, except for directing
// to a specific upstream. This method adjusts headers and other relevant
// properties of the cloned request and should be done just once (before
// proxying) regardless of proxy retries. This assumes that no mutations
// of the cloned request are performed by h during or after proxying.
func (h Handler) prepareRequest(req *http.Request, repl *caddy.Replacer) (*http.Request, error) {
	req = cloneRequest(req)

	// if enabled, perform rewrites on the cloned request; if
	// the method is GET or HEAD, prevent the request body
	// from being copied to the upstream
	if h.Rewrite != nil {
		changed := h.Rewrite.Rewrite(req, repl)
		if changed && (h.Rewrite.Method == "GET" || h.Rewrite.Method == "HEAD") {
			req.ContentLength = 0
			req.Body = nil
		}
	}

	// if enabled, buffer client request; this should only be
	// enabled if the upstream requires it and does not work
	// with "slow clients" (gunicorn, etc.) - this obviously
	// has a perf overhead and makes the proxy at risk of
	// exhausting memory and more susceptible to slowloris
	// attacks, so it is strongly recommended to only use this
	// feature if absolutely required, if read timeouts are
	// set, and if body size is limited
	if (h.BufferRequests || isChunkedRequest(req)) && req.Body != nil {
		req.Body, req.ContentLength = h.bufferedBody(req.Body)
		req.Header.Set("Content-Length", strconv.FormatInt(req.ContentLength, 10))
	}

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

	// Add the supported X-Forwarded-* headers
	err := h.addForwardedHeaders(req)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// addForwardedHeaders adds the de-facto standard X-Forwarded-*
// headers to the request before it is sent upstream.
//
// These headers are security sensitive, so care is taken to only
// use existing values for these headers from the incoming request
// if the client IP is trusted (i.e. coming from a trusted proxy
// sitting in front of this server). If the request didn't have
// the headers at all, then they will be added with the values
// that we can glean from the request.
func (h Handler) addForwardedHeaders(req *http.Request) error {
	// Parse the remote IP, ignore the error as non-fatal,
	// but the remote IP is required to continue, so we
	// just return early. This should probably never happen
	// though, unless some other module manipulated the request's
	// remote address and used an invalid value.
	clientIP, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		// Remove the `X-Forwarded-*` headers to avoid upstreams
		// potentially trusting a header that came from the client
		req.Header.Del("X-Forwarded-For")
		req.Header.Del("X-Forwarded-Proto")
		req.Header.Del("X-Forwarded-Host")
		return nil
	}

	// Client IP may contain a zone if IPv6, so we need
	// to pull that out before parsing the IP
	clientIP, _, _ = strings.Cut(clientIP, "%")
	ipAddr, err := netip.ParseAddr(clientIP)
	if err != nil {
		return fmt.Errorf("invalid IP address: '%s': %v", clientIP, err)
	}

	// Check if the client is a trusted proxy
	trusted := caddyhttp.GetVar(req.Context(), caddyhttp.TrustedProxyVarKey).(bool)
	for _, ipRange := range h.trustedProxies {
		if ipRange.Contains(ipAddr) {
			trusted = true
			break
		}
	}

	// If we aren't the first proxy, and the proxy is trusted,
	// retain prior X-Forwarded-For information as a comma+space
	// separated list and fold multiple headers into one.
	clientXFF := clientIP
	prior, ok, omit := allHeaderValues(req.Header, "X-Forwarded-For")
	if trusted && ok && prior != "" {
		clientXFF = prior + ", " + clientXFF
	}
	if !omit {
		req.Header.Set("X-Forwarded-For", clientXFF)
	}

	// Set X-Forwarded-Proto; many backend apps expect this,
	// so that they can properly craft URLs with the right
	// scheme to match the original request
	proto := "https"
	if req.TLS == nil {
		proto = "http"
	}
	prior, ok, omit = lastHeaderValue(req.Header, "X-Forwarded-Proto")
	if trusted && ok && prior != "" {
		proto = prior
	}
	if !omit {
		req.Header.Set("X-Forwarded-Proto", proto)
	}

	// Set X-Forwarded-Host; often this is redundant because
	// we pass through the request Host as-is, but in situations
	// where we proxy over HTTPS, the user may need to override
	// Host themselves, so it's helpful to send the original too.
	host := req.Host
	prior, ok, omit = lastHeaderValue(req.Header, "X-Forwarded-Host")
	if trusted && ok && prior != "" {
		host = prior
	}
	if !omit {
		req.Header.Set("X-Forwarded-Host", host)
	}

	return nil
}

// reverseProxy performs a round-trip to the given backend and processes the response with the client.
// (This method is mostly the beginning of what was borrowed from the net/http/httputil package in the
// Go standard library which was used as the foundation.)
func (h *Handler) reverseProxy(rw http.ResponseWriter, req *http.Request, origReq *http.Request, repl *caddy.Replacer, di DialInfo, next caddyhttp.Handler) error {
	_ = di.Upstream.Host.countRequest(1)
	//nolint:errcheck
	defer di.Upstream.Host.countRequest(-1)

	// point the request to this upstream
	h.directRequest(req, di)

	server := req.Context().Value(caddyhttp.ServerCtxKey).(*caddyhttp.Server)
	shouldLogCredentials := server.Logs != nil && server.Logs.ShouldLogCredentials

	if supports1xx {
		// Forward 1xx status codes, backported from https://github.com/golang/go/pull/53164
		trace := &httptrace.ClientTrace{
			Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
				h := rw.Header()
				copyHeader(h, http.Header(header))
				rw.WriteHeader(code)

				// Clear headers coming from the backend
				// (it's not automatically done by ResponseWriter.WriteHeader() for 1xx responses)
				for k := range header {
					delete(h, k)
				}

				return nil
			},
		}
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	}

	// if FlushInterval is explicitly configured to -1 (i.e. flush continuously to achieve
	// low-latency streaming), don't let the transport cancel the request if the client
	// disconnects: user probably wants us to finish sending the data to the upstream
	// regardless, and we should expect client disconnection in low-latency streaming
	// scenarios (see issue #4922)
	if h.FlushInterval == -1 {
		req = req.WithContext(ignoreClientGoneContext{req.Context(), h.ctx.Done()})
	}

	// do the round-trip; emit debug log with values we know are
	// safe, or if there is no error, emit fuller log entry
	start := time.Now()
	res, err := h.Transport.RoundTrip(req)
	duration := time.Since(start)
	logger := h.logger.With(
		zap.String("upstream", di.Upstream.String()),
		zap.Duration("duration", duration),
		zap.Object("request", caddyhttp.LoggableHTTPRequest{
			Request:              req,
			ShouldLogCredentials: shouldLogCredentials,
		}),
	)
	if err != nil {
		logger.Debug("upstream roundtrip", zap.Error(err))
		return err
	}
	logger.Debug("upstream roundtrip",
		zap.Object("headers", caddyhttp.LoggableHTTPHeader{
			Header:               res.Header,
			ShouldLogCredentials: shouldLogCredentials,
		}),
		zap.Int("status", res.StatusCode))

	// duration until upstream wrote response headers (roundtrip duration)
	repl.Set("http.reverse_proxy.upstream.latency", duration)
	repl.Set("http.reverse_proxy.upstream.latency_ms", duration.Seconds()*1e3) // multiply seconds to preserve decimal (see #4666)

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
		res.Body, _ = h.bufferedBody(res.Body)
	}

	// see if any response handler is configured for this response from the backend
	for i, rh := range h.HandleResponse {
		if rh.Match != nil && !rh.Match.Match(res.StatusCode, res.Header) {
			continue
		}

		// if configured to only change the status code,
		// do that then continue regular proxy response
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

		// set up the replacer so that parts of the original response can be
		// used for routing decisions
		for field, value := range res.Header {
			repl.Set("http.reverse_proxy.header."+field, strings.Join(value, ","))
		}
		repl.Set("http.reverse_proxy.status_code", res.StatusCode)
		repl.Set("http.reverse_proxy.status_text", res.Status)

		h.logger.Debug("handling response", zap.Int("handler", i))

		// we make some data available via request context to child routes
		// so that they may inherit some options and functions from the
		// handler, and be able to copy the response.
		// we use the original request here, so that any routes from 'next'
		// see the original request rather than the proxy cloned request.
		hrc := &handleResponseContext{
			handler:  h,
			response: res,
			start:    start,
			logger:   logger,
		}
		ctx := origReq.Context()
		ctx = context.WithValue(ctx, proxyHandleResponseContextCtxKey, hrc)

		// pass the request through the response handler routes
		routeErr := rh.Routes.Compile(next).ServeHTTP(rw, origReq.WithContext(ctx))

		// close the response body afterwards, since we don't need it anymore;
		// either a route had 'copy_response' which already consumed the body,
		// or some other terminal handler ran which doesn't need the response
		// body after that point (e.g. 'file_server' for X-Accel-Redirect flow),
		// or we fell through to subsequent handlers past this proxy
		// (e.g. forward auth's 2xx response flow).
		if !hrc.isFinalized {
			res.Body.Close()
		}

		// wrap any route error in roundtripSucceeded so caller knows that
		// the roundtrip was successful and to not retry
		if routeErr != nil {
			return roundtripSucceeded{routeErr}
		}

		// we're done handling the response, and we don't want to
		// fall through to the default finalize/copy behaviour
		return nil
	}

	// copy the response body and headers back to the upstream client
	return h.finalizeResponse(rw, req, res, repl, start, logger)
}

// finalizeResponse prepares and copies the response.
func (h Handler) finalizeResponse(
	rw http.ResponseWriter,
	req *http.Request,
	res *http.Response,
	repl *caddy.Replacer,
	start time.Time,
	logger *zap.Logger,
) error {
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

	err := h.copyResponse(rw, res.Body, h.flushInterval(req, res))
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
	repl.Set("http.reverse_proxy.upstream.duration", time.Since(start))
	repl.Set("http.reverse_proxy.upstream.duration_ms", time.Since(start).Seconds()*1e3)

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

// tryAgain takes the time that the handler was initially invoked,
// the amount of retries already performed, as well as any error
// currently obtained, and the request being tried, and returns
// true if another attempt should be made at proxying the request.
// If true is returned, it has already blocked long enough before
// the next retry (i.e. no more sleeping is needed). If false is
// returned, the handler should stop trying to proxy the request.
func (lb LoadBalancing) tryAgain(ctx caddy.Context, start time.Time, retries int, proxyErr error, req *http.Request) bool {
	// no retries are configured
	if lb.TryDuration == 0 && lb.Retries == 0 {
		return false
	}

	// if we've tried long enough, break
	if lb.TryDuration > 0 && time.Since(start) >= time.Duration(lb.TryDuration) {
		return false
	}

	// if we've reached the retry limit, break
	if lb.Retries > 0 && retries >= lb.Retries {
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

	// fast path; if the interval is zero, we don't need to wait
	if lb.TryInterval == 0 {
		return true
	}

	// otherwise, wait and try the next available host
	timer := time.NewTimer(time.Duration(lb.TryInterval))
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		if !timer.Stop() {
			// if the timer has been stopped then read from the channel
			<-timer.C
		}
		return false
	}
}

// directRequest modifies only req.URL so that it points to the upstream
// in the given DialInfo. It must modify ONLY the request URL.
func (Handler) directRequest(req *http.Request, di DialInfo) {
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

func (h Handler) provisionUpstream(upstream *Upstream) {
	// create or get the host representation for this upstream
	upstream.fillHost()

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

// bufferedBody reads originalBody into a buffer, then returns a reader for the buffer.
// Always close the return value when done with it, just like if it was the original body!
func (h Handler) bufferedBody(originalBody io.ReadCloser) (io.ReadCloser, int64) {
	var written int64
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	if h.MaxBufferSize > 0 {
		n, err := io.CopyN(buf, originalBody, h.MaxBufferSize)
		if err != nil || n == h.MaxBufferSize {
			return bodyReadCloser{
				Reader: io.MultiReader(buf, originalBody),
				buf:    buf,
				body:   originalBody,
			}, n
		}
	} else {
		written, _ = io.Copy(buf, originalBody)
	}
	originalBody.Close() // no point in keeping it open
	return bodyReadCloser{
		Reader: buf,
		buf:    buf,
	}, written
}

func isChunkedRequest(req *http.Request) bool {
	for _, transferEncoding := range req.TransferEncoding {
		if transferEncoding == "chunked" {
			return true
		}
	}
	return false
}

// cloneRequest makes a semi-deep clone of origReq.
//
// Most of this code is borrowed from the Go stdlib reverse proxy,
// but we make a shallow-ish clone the request (deep clone only
// the headers and URL) so we can avoid manipulating the original
// request when using it to proxy upstream. This prevents request
// corruption and data races.
func cloneRequest(origReq *http.Request) *http.Request {
	req := new(http.Request)
	*req = *origReq
	if origReq.URL != nil {
		newURL := new(url.URL)
		*newURL = *origReq.URL
		if origReq.URL.User != nil {
			newURL.User = new(url.Userinfo)
			*newURL.User = *origReq.URL.User
		}
		// sanitize the request URL; we expect it to not contain the
		// scheme and host since those should be determined by r.TLS
		// and r.Host respectively, but some clients may include it
		// in the request-line, which is technically valid in HTTP,
		// but breaks reverseproxy behaviour, overriding how the
		// dialer will behave. See #4237 for context.
		newURL.Scheme = ""
		newURL.Host = ""
		req.URL = newURL
	}
	if origReq.Header != nil {
		req.Header = origReq.Header.Clone()
	}
	if origReq.Trailer != nil {
		req.Trailer = origReq.Trailer.Clone()
	}
	return req
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// allHeaderValues gets all values for a given header field,
// joined by a comma and space if more than one is set. If the
// header field is nil, then the omit is true, meaning some
// earlier logic in the server wanted to prevent this header from
// getting written at all. If the header is empty, then ok is
// false. Callers should still check that the value is not empty
// (the header field may be set but have an empty value).
func allHeaderValues(h http.Header, field string) (value string, ok bool, omit bool) {
	values, ok := h[http.CanonicalHeaderKey(field)]
	if ok && values == nil {
		return "", true, true
	}
	if len(values) == 0 {
		return "", false, false
	}
	return strings.Join(values, ", "), true, false
}

// lastHeaderValue gets the last value for a given header field
// if more than one is set. If the header field is nil, then
// the omit is true, meaning some earlier logic in the server
// wanted to prevent this header from getting written at all.
// If the header is empty, then ok is false. Callers should
// still check that the value is not empty (the header field
// may be set but have an empty value).
func lastHeaderValue(h http.Header, field string) (value string, ok bool, omit bool) {
	values, ok := h[http.CanonicalHeaderKey(field)]
	if ok && values == nil {
		return "", true, true
	}
	if len(values) == 0 {
		return "", false, false
	}
	return values[len(values)-1], true, false
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
	for _, f := range h["Connection"] {
		for _, sf := range strings.Split(f, ",") {
			if sf = textproto.TrimString(sf); sf != "" {
				h.Del(sf)
			}
		}
	}
}

// statusError returns an error value that has a status code.
func statusError(err error) error {
	// errors proxying usually mean there is a problem with the upstream(s)
	statusCode := http.StatusBadGateway

	// timeout errors have a standard status code (see issue #4823)
	if err, ok := err.(net.Error); ok && err.Timeout() {
		statusCode = http.StatusGatewayTimeout
	}

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

	// How many times to retry selecting available backends for each
	// request if the next available host is down. If try_duration is
	// also configured, then retries may stop early if the duration
	// is reached. By default, retries are disabled (zero).
	Retries int `json:"retries,omitempty"`

	// How long to try selecting available backends for each request
	// if the next available host is down. Clients will wait for up
	// to this long while the load balancer tries to find an available
	// upstream host. If retries is also configured, tries may stop
	// early if the maximum retries is reached. By default, retries
	// are disabled (zero duration).
	TryDuration caddy.Duration `json:"try_duration,omitempty"`

	// How long to wait between selecting the next host from the pool.
	// Default is 250ms if try_duration is enabled, otherwise zero. Only
	// relevant when a request to an upstream host fails. Be aware that
	// setting this to 0 with a non-zero try_duration can cause the CPU
	// to spin if all backends are down and latency is very low.
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

// UpstreamSource gets the list of upstreams that can be used when
// proxying a request. Returned upstreams will be load balanced and
// health-checked. This should be a very fast function -- instant
// if possible -- and the return value must be as stable as possible.
// In other words, the list of upstreams should ideally not change much
// across successive calls. If the list of upstreams changes or the
// ordering is not stable, load balancing will suffer. This function
// may be called during each retry, multiple times per request, and as
// such, needs to be instantaneous. The returned slice will not be
// modified.
type UpstreamSource interface {
	GetUpstreams(*http.Request) ([]*Upstream, error)
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
	New: func() any {
		return new(bytes.Buffer)
	},
}

// handleResponseContext carries some contextual information about the
// current proxy handling.
type handleResponseContext struct {
	// handler is the active proxy handler instance, so that
	// routes like copy_response may inherit some config
	// options and have access to handler methods.
	handler *Handler

	// response is the actual response received from the proxy
	// roundtrip, to potentially be copied if a copy_response
	// handler is in the handle_response routes.
	response *http.Response

	// start is the time just before the proxy roundtrip was
	// performed, used for logging.
	start time.Time

	// logger is the prepared logger which is used to write logs
	// with the request, duration, and selected upstream attached.
	logger *zap.Logger

	// isFinalized is whether the response has been finalized,
	// i.e. copied and closed, to make sure that it doesn't
	// happen twice.
	isFinalized bool
}

// ignoreClientGoneContext is a special context.Context type
// intended for use when doing a RoundTrip where you don't
// want a client disconnection to cancel the request during
// the roundtrip. Set its done field to a Done() channel
// of a context that doesn't get canceled when the client
// disconnects, such as caddy.Context.Done() instead.
type ignoreClientGoneContext struct {
	context.Context
	done <-chan struct{}
}

func (c ignoreClientGoneContext) Done() <-chan struct{} { return c.done }

// proxyHandleResponseContextCtxKey is the context key for the active proxy handler
// so that handle_response routes can inherit some config options
// from the proxy handler.
const proxyHandleResponseContextCtxKey caddy.CtxKey = "reverse_proxy_handle_response_context"

// Interface guards
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.CleanerUpper          = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)
