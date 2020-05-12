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
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
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
// both within and after this handler):
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
	// be avoided if at all possible for performance reasons.
	BufferRequests bool `json:"buffer_requests,omitempty"`

	Transport http.RoundTripper `json:"-"`
	CB        CircuitBreaker    `json:"-"`

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
	h.logger = ctx.Logger(h)

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
				MaxIdleConnsPerHost: 32,
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

	// if active health checks are enabled, configure them and start a worker
	if h.HealthChecks != nil &&
		h.HealthChecks.Active != nil &&
		(h.HealthChecks.Active.Path != "" || h.HealthChecks.Active.Port != 0) {
		h.HealthChecks.Active.logger = h.logger.Named("health_checker.active")

		timeout := time.Duration(h.HealthChecks.Active.Timeout)
		if timeout == 0 {
			timeout = 5 * time.Second
		}

		h.HealthChecks.Active.stopChan = make(chan struct{})
		h.HealthChecks.Active.httpClient = &http.Client{
			Timeout:   timeout,
			Transport: h.Transport,
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

	return nil
}

// Cleanup cleans up the resources made by h during provisioning.
func (h *Handler) Cleanup() error {
	// stop the active health checker
	if h.HealthChecks != nil &&
		h.HealthChecks.Active != nil &&
		h.HealthChecks.Active.stopChan != nil {
		// TODO: consider using context cancellation, could be much simpler
		close(h.HealthChecks.Active.stopChan)
	}

	// TODO: Close keepalive connections on reload? https://github.com/caddyserver/caddy/pull/2507/files#diff-70219fd88fe3f36834f474ce6537ed26R762

	// remove hosts from our config from the pool
	for _, upstream := range h.Upstreams {
		hosts.Delete(upstream.String())
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
		buf := bufPool.Get().(*bytes.Buffer)
		buf.Reset()
		defer bufPool.Put(buf)
		io.Copy(buf, r.Body)
		r.Body.Close()
		r.Body = ioutil.NopCloser(buf)
	}

	// prepare the request for proxying; this is needed only once
	err := h.prepareRequest(r)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError,
			fmt.Errorf("preparing request for upstream round-trip: %v", err))
	}

	// we will need the original headers and Host
	// value if header operations are configured
	reqHeader := r.Header
	reqHost := r.Host

	start := time.Now()

	var proxyErr error
	for {
		// choose an available upstream
		upstream := h.LoadBalancing.SelectionPolicy.Select(h.Upstreams, r)
		if upstream == nil {
			if proxyErr == nil {
				proxyErr = fmt.Errorf("no upstreams available")
			}
			if !h.LoadBalancing.tryAgain(start, proxyErr, r) {
				break
			}
			continue
		}

		// the dial address may vary per-request if placeholders are
		// used, so perform those replacements here; the resulting
		// DialInfo struct should have valid network address syntax
		dialInfo, err := upstream.fillDialInfo(r)
		if err != nil {
			return fmt.Errorf("making dial info: %v", err)
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
		proxyErr = h.reverseProxy(w, r, dialInfo)
		if proxyErr == nil || proxyErr == context.Canceled {
			// context.Canceled happens when the downstream client
			// cancels the request, which is not our failure
			return nil
		}

		// remember this failure (if enabled)
		h.countFailure(upstream)

		// if we've tried long enough, break
		if !h.LoadBalancing.tryAgain(start, proxyErr, r) {
			break
		}
	}

	return caddyhttp.Error(http.StatusBadGateway, proxyErr)
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
	for _, h := range hopHeaders {
		hv := req.Header.Get(h)
		if hv == "" {
			continue
		}
		if h == "Te" && hv == "trailers" {
			// Issue golang/go#21096: tell backend applications that
			// care about trailer support that we support
			// trailers. (We do, but we don't go out of
			// our way to advertise that unless the
			// incoming client request thought it was
			// worth mentioning)
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

	// set X-Forwarded-Proto; many backend apps expect this too
	proto := "https"
	if req.TLS == nil {
		proto = "http"
	}
	req.Header.Set("X-Forwarded-Proto", proto)

	return nil
}

// reverseProxy performs a round-trip to the given backend and processes the response with the client.
// (This method is mostly the beginning of what was borrowed from the net/http/httputil package in the
// Go standard library which was used as the foundation.)
func (h *Handler) reverseProxy(rw http.ResponseWriter, req *http.Request, di DialInfo) error {
	di.Upstream.Host.CountRequest(1)
	defer di.Upstream.Host.CountRequest(-1)

	// point the request to this upstream
	h.directRequest(req, di)

	// do the round-trip
	start := time.Now()
	res, err := h.Transport.RoundTrip(req)
	duration := time.Since(start)
	if err != nil {
		return err
	}

	h.logger.Debug("upstream roundtrip",
		zap.String("upstream", di.Upstream.String()),
		zap.Object("request", caddyhttp.LoggableHTTPRequest{Request: req}),
		zap.Object("headers", caddyhttp.LoggableHTTPHeader(res.Header)),
		zap.Duration("duration", duration),
		zap.Int("status", res.StatusCode),
	)

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

	// Deal with 101 Switching Protocols responses: (WebSocket, h2c, etc)
	if res.StatusCode == http.StatusSwitchingProtocols {
		h.handleUpgradeResponse(rw, req, res)
		return nil
	}

	removeConnectionHeaders(res.Header)

	for _, h := range hopHeaders {
		res.Header.Del(h)
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

	// apply any response header operations
	if h.Headers != nil && h.Headers.Response != nil {
		if h.Headers.Response.Require == nil ||
			h.Headers.Response.Require.Match(res.StatusCode, rw.Header()) {
			repl := req.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
			h.Headers.Response.ApplyTo(rw.Header(), repl)
		}
	}

	// TODO: there should be an option to return an error if the response
	// matches some criteria; would solve https://github.com/caddyserver/caddy/issues/1447
	// by allowing the backend to determine whether this server should treat
	// a 400+ status code as an error -- but we might need to be careful that
	// we do not affect the health status of the backend... still looking into
	// that; if we need to avoid that, we should return a particular error type
	// that the caller of this function checks for and only applies health
	// status changes if the error is not this special type

	rw.WriteHeader(res.StatusCode)

	err = h.copyResponse(rw, res.Body, h.flushInterval(req, res))
	if err != nil {
		defer res.Body.Close()
		// Since we're streaming the response, if we run into an error all we can do
		// is abort the request. Issue golang/go#23643: ReverseProxy should use ErrAbortHandler
		// on read error while copying body.
		// TODO: Look into whether we want to panic at all in our case...
		if !shouldPanicOnCopyError(req) {
			// p.logf("suppressing panic for copyResponse error in test; copy error: %v", err)
			return err
		}

		panic(http.ErrAbortHandler)
	}
	res.Body.Close() // close now, instead of defer, to populate res.Trailer

	if len(res.Trailer) > 0 {
		// Force chunking if we saw a response trailer.
		// This prevents net/http from calculating the length for short
		// bodies and adding a Content-Length.
		if fl, ok := rw.(http.Flusher); ok {
			fl.Flush()
		}
	}

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
func (lb LoadBalancing) tryAgain(start time.Time, proxyErr error, req *http.Request) bool {
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
	time.Sleep(time.Duration(lb.TryInterval))
	return true
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

// shouldPanicOnCopyError reports whether the reverse proxy should
// panic with http.ErrAbortHandler. This is the right thing to do by
// default, but Go 1.10 and earlier did not, so existing unit tests
// weren't expecting panics. Only panic in our own tests, or when
// running under the HTTP server.
// TODO: I don't know if we want this at all...
func shouldPanicOnCopyError(req *http.Request) bool {
	// if inOurTests {
	// 	// Our tests know to handle this panic.
	// 	return true
	// }
	if req.Context().Value(http.ServerContextKey) != nil {
		// We seem to be running under an HTTP server, so
		// it'll recover the panic.
		return true
	}
	// Otherwise act like Go 1.10 and earlier to not break
	// existing tests.
	return false
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func cloneHeader(h http.Header) http.Header {
	h2 := make(http.Header, len(h))
	for k, vv := range h {
		vv2 := make([]string, len(vv))
		copy(vv2, vv)
		h2[k] = vv2
	}
	return h2
}

func upgradeType(h http.Header) string {
	if !httpguts.HeaderValuesContainsToken(h["Connection"], "Upgrade") {
		return ""
	}
	return strings.ToLower(h.Get("Upgrade"))
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
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
	Select(UpstreamPool, *http.Request) *Upstream
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
