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
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"golang.org/x/net/http/httpguts"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler implements a highly configurable and production-ready reverse proxy.
type Handler struct {
	TransportRaw  json.RawMessage `json:"transport,omitempty"`
	CBRaw         json.RawMessage `json:"circuit_breaker,omitempty"`
	LoadBalancing *LoadBalancing  `json:"load_balancing,omitempty"`
	HealthChecks  *HealthChecks   `json:"health_checks,omitempty"`
	Upstreams     UpstreamPool    `json:"upstreams,omitempty"`
	FlushInterval caddy.Duration  `json:"flush_interval,omitempty"`

	Transport http.RoundTripper `json:"-"`
	CB        CircuitBreaker    `json:"-"`
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		Name: "http.handlers.reverse_proxy",
		New:  func() caddy.Module { return new(Handler) },
	}
}

// Provision ensures that h is set up properly before use.
func (h *Handler) Provision(ctx caddy.Context) error {
	// start by loading modules
	if h.TransportRaw != nil {
		val, err := ctx.LoadModuleInline("protocol", "http.handlers.reverse_proxy.transport", h.TransportRaw)
		if err != nil {
			return fmt.Errorf("loading transport module: %s", err)
		}
		h.Transport = val.(http.RoundTripper)
		h.TransportRaw = nil // allow GC to deallocate - TODO: Does this help?
	}
	if h.LoadBalancing != nil && h.LoadBalancing.SelectionPolicyRaw != nil {
		val, err := ctx.LoadModuleInline("policy",
			"http.handlers.reverse_proxy.selection_policies",
			h.LoadBalancing.SelectionPolicyRaw)
		if err != nil {
			return fmt.Errorf("loading load balancing selection module: %s", err)
		}
		h.LoadBalancing.SelectionPolicy = val.(Selector)
		h.LoadBalancing.SelectionPolicyRaw = nil // allow GC to deallocate - TODO: Does this help?
	}
	if h.CBRaw != nil {
		val, err := ctx.LoadModuleInline("type", "http.handlers.reverse_proxy.circuit_breakers", h.CBRaw)
		if err != nil {
			return fmt.Errorf("loading circuit breaker module: %s", err)
		}
		h.CB = val.(CircuitBreaker)
		h.CBRaw = nil // allow GC to deallocate - TODO: Does this help?
	}

	if h.Transport == nil {
		t := &HTTPTransport{
			KeepAlive: &KeepAlive{
				ProbeInterval:   caddy.Duration(30 * time.Second),
				IdleConnTimeout: caddy.Duration(2 * time.Minute),
			},
			DialTimeout: caddy.Duration(10 * time.Second),
		}
		err := t.Provision(ctx)
		if err != nil {
			return fmt.Errorf("provisioning default transport: %v", err)
		}
		h.Transport = t
	}

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

	// if active health checks are enabled, configure them and start a worker
	if h.HealthChecks != nil &&
		h.HealthChecks.Active != nil &&
		(h.HealthChecks.Active.Path != "" || h.HealthChecks.Active.Port != 0) {
		timeout := time.Duration(h.HealthChecks.Active.Timeout)
		if timeout == 0 {
			timeout = 10 * time.Second
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

	var allUpstreams []*Upstream
	for _, upstream := range h.Upstreams {
		// if a port was not specified (and the network type uses
		// ports), then maybe we can figure out the default port
		netw, host, port, err := caddy.SplitNetworkAddress(upstream.Dial)
		if err != nil && port == "" && !strings.Contains(netw, "unix") {
			if host == "" {
				// assume all that was given was the host, no port
				host = upstream.Dial
			}
			// a port was not specified, but we may be able to
			// infer it if we know the standard ports on which
			// the transport protocol operates
			if ht, ok := h.Transport.(*HTTPTransport); ok {
				defaultPort := "80"
				if ht.TLS != nil {
					defaultPort = "443"
				}
				upstream.Dial = caddy.JoinNetworkAddress(netw, host, defaultPort)
			}
		}

		// upstreams are allowed to map to only a single host,
		// but an upstream's address may semantically represent
		// multiple addresses, so make sure to handle each
		// one in turn based on this one upstream config
		network, addresses, err := caddy.ParseNetworkAddress(upstream.Dial)
		if err != nil {
			return fmt.Errorf("parsing dial address: %v", err)
		}

		for _, addr := range addresses {
			// make a new upstream based on the original
			// that has a singular dial address
			upstreamCopy := *upstream
			upstreamCopy.dialInfo = DialInfo{network, addr}
			upstreamCopy.Dial = upstreamCopy.dialInfo.String()
			upstreamCopy.cb = h.CB

			// if host already exists from a current config,
			// use that instead; otherwise, add it
			// TODO: make hosts modular, so that their state can be distributed in enterprise for example
			// TODO: If distributed, the pool should be stored in storage...
			var host Host = new(upstreamHost)
			activeHost, loaded := hosts.LoadOrStore(upstreamCopy.Dial, host)
			if loaded {
				host = activeHost.(Host)
			}
			upstreamCopy.Host = host

			// if the passive health checker has a non-zero "unhealthy
			// request count" but the upstream has no MaxRequests set
			// (they are the same thing, but one is a default value for
			// for upstreams with a zero MaxRequests), copy the default
			// value into this upstream, since the value in the upstream
			// (MaxRequests) is what is used during availability checks
			if h.HealthChecks != nil &&
				h.HealthChecks.Passive != nil &&
				h.HealthChecks.Passive.UnhealthyRequestCount > 0 &&
				upstreamCopy.MaxRequests == 0 {
				upstreamCopy.MaxRequests = h.HealthChecks.Passive.UnhealthyRequestCount
			}

			// upstreams need independent access to the passive
			// health check policy because they run outside of the
			// scope of a request handler
			if h.HealthChecks != nil {
				upstreamCopy.healthCheckPolicy = h.HealthChecks.Passive
			}

			allUpstreams = append(allUpstreams, &upstreamCopy)
		}
	}

	// replace the unmarshaled upstreams (possible 1:many
	// address mapping) with our list, which is mapped 1:1,
	// thus may have expanded the original list
	h.Upstreams = allUpstreams

	return nil
}

// Cleanup cleans up the resources made by h during provisioning.
func (h *Handler) Cleanup() error {
	// stop the active health checker
	if h.HealthChecks != nil &&
		h.HealthChecks.Active != nil &&
		h.HealthChecks.Active.stopChan != nil {
		close(h.HealthChecks.Active.stopChan)
	}

	// remove hosts from our config from the pool
	for _, upstream := range h.Upstreams {
		hosts.Delete(upstream.dialInfo.String())
	}

	return nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// prepare the request for proxying; this is needed only once
	err := h.prepareRequest(r)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError,
			fmt.Errorf("preparing request for upstream round-trip: %v", err))
	}

	start := time.Now()

	var proxyErr error
	for {
		// choose an available upstream
		upstream := h.LoadBalancing.SelectionPolicy.Select(h.Upstreams, r)
		if upstream == nil {
			if proxyErr == nil {
				proxyErr = fmt.Errorf("no available upstreams")
			}
			if !h.tryAgain(start, proxyErr) {
				break
			}
			continue
		}

		// attach to the request information about how to dial the upstream;
		// this is necessary because the information cannot be sufficiently
		// or satisfactorily represented in a URL
		ctx := context.WithValue(r.Context(), DialInfoCtxKey, upstream.dialInfo)
		r = r.WithContext(ctx)

		// proxy the request to that upstream
		proxyErr = h.reverseProxy(w, r, upstream)
		if proxyErr == nil || proxyErr == context.Canceled {
			// context.Canceled happens when the downstream client
			// cancels the request; we don't have to worry about that
			return nil
		}

		// remember this failure (if enabled)
		h.countFailure(upstream)

		// if we've tried long enough, break
		if !h.tryAgain(start, proxyErr) {
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
	// as a special (but very common) case, if the transport
	// is HTTP, then ensure the request has the proper scheme
	// because incoming requests by default are lacking it
	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
		if ht, ok := h.Transport.(*HTTPTransport); ok && ht.TLS != nil {
			req.URL.Scheme = "https"
		}
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

	return nil
}

// reverseProxy performs a round-trip to the given backend and processes the response with the client.
// (This method is mostly the beginning of what was borrowed from the net/http/httputil package in the
// Go standard library which was used as the foundation.)
func (h *Handler) reverseProxy(rw http.ResponseWriter, req *http.Request, upstream *Upstream) error {
	upstream.Host.CountRequest(1)
	defer upstream.Host.CountRequest(-1)

	// point the request to this upstream
	h.directRequest(req, upstream)

	// do the round-trip
	start := time.Now()
	res, err := h.Transport.RoundTrip(req)
	latency := time.Since(start)
	if err != nil {
		return err
	}

	// update circuit breaker on current conditions
	if upstream.cb != nil {
		upstream.cb.RecordMetric(res.StatusCode, latency)
	}

	// perform passive health checks (if enabled)
	if h.HealthChecks != nil && h.HealthChecks.Passive != nil {
		// strike if the status code matches one that is "bad"
		for _, badStatus := range h.HealthChecks.Passive.UnhealthyStatus {
			if caddyhttp.StatusCodeMatches(res.StatusCode, badStatus) {
				h.countFailure(upstream)
			}
		}

		// strike if the roundtrip took too long
		if h.HealthChecks.Passive.UnhealthyLatency > 0 &&
			latency >= time.Duration(h.HealthChecks.Passive.UnhealthyLatency) {
			h.countFailure(upstream)
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
// as well as any error currently obtained and returns true if
// another attempt should be made at proxying the request. If
// true is returned, it has already blocked long enough before
// the next retry (i.e. no more sleeping is needed). If false is
// returned, the handler should stop trying to proxy the request.
func (h Handler) tryAgain(start time.Time, proxyErr error) bool {
	// if downstream has canceled the request, break
	if proxyErr == context.Canceled {
		return false
	}
	// if we've tried long enough, break
	if time.Since(start) >= time.Duration(h.LoadBalancing.TryDuration) {
		return false
	}
	// otherwise, wait and try the next available host
	time.Sleep(time.Duration(h.LoadBalancing.TryInterval))
	return true
}

// directRequest modifies only req.URL so that it points to the
// given upstream host. It must modify ONLY the request URL.
func (h Handler) directRequest(req *http.Request, upstream *Upstream) {
	if req.URL.Host == "" {
		// we need a host, so set the upstream's host address
		fullHost := upstream.dialInfo.Address

		// but if the port matches the scheme, strip the port because
		// it's weird to make a request like http://example.com:80/.
		host, port, err := net.SplitHostPort(fullHost)
		if err == nil &&
			(req.URL.Scheme == "http" && port == "80") ||
			(req.URL.Scheme == "https" && port == "443") {
			fullHost = host
		}

		req.URL.Host = fullHost
	}
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
	SelectionPolicyRaw json.RawMessage `json:"selection_policy,omitempty"`
	TryDuration        caddy.Duration  `json:"try_duration,omitempty"`
	TryInterval        caddy.Duration  `json:"try_interval,omitempty"`

	SelectionPolicy Selector `json:"-"`
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

// TODO: see if we can use this
// var bufPool = sync.Pool{
// 	New: func() interface{} {
// 		return new(bytes.Buffer)
// 	},
// }

// Interface guards
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.CleanerUpper          = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)
