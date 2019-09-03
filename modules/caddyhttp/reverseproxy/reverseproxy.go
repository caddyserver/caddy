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
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"golang.org/x/net/http/httpguts"
)

func init() {
	caddy.RegisterModule(Handler{})
}

type Handler struct {
	TransportRaw  json.RawMessage `json:"transport,omitempty"`
	LoadBalancing *LoadBalancing  `json:"load_balancing,omitempty"`
	HealthChecks  *HealthChecks   `json:"health_checks,omitempty"`
	// UpstreamStorageRaw json.RawMessage `json:"upstream_storage,omitempty"` // TODO:
	Upstreams HostPool `json:"upstreams,omitempty"`

	// UpstreamProvider UpstreamProvider  `json:"-"` // TODO:
	Transport http.RoundTripper `json:"-"`
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		Name: "http.handlers.reverse_proxy",
		New:  func() caddy.Module { return new(Handler) },
	}
}

func (h *Handler) Provision(ctx caddy.Context) error {
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

	if h.Transport == nil {
		h.Transport = defaultTransport
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
		// upstream is local or low-latency; default to some
		// sane waiting period before try attempts
		h.LoadBalancing.TryInterval = caddy.Duration(250 * time.Millisecond)
	}

	for _, upstream := range h.Upstreams {
		// url parser requires a scheme
		if !strings.Contains(upstream.Address, "://") {
			upstream.Address = "http://" + upstream.Address
		}
		u, err := url.Parse(upstream.Address)
		if err != nil {
			return fmt.Errorf("invalid upstream address %s: %v", upstream.Address, err)
		}
		upstream.hostURL = u

		// if host already exists from a current config,
		// use that instead; otherwise, add it
		// TODO: make hosts modular, so that their state can be distributed in enterprise for example
		// TODO: If distributed, the pool should be stored in storage...
		var host Host = new(upstreamHost)
		activeHost, loaded := hosts.LoadOrStore(u.String(), host)
		if loaded {
			host = activeHost.(Host)
		}
		upstream.Host = host

		// if the passive health checker has a non-zero "unhealthy
		// request count" but the upstream has no MaxRequests set
		// (they are the same thing, but one is a default value for
		// for upstreams with a zero MaxRequests), copy the default
		// value into this upstream, since the value in the upstream
		// is what is used during availability checks
		if h.HealthChecks != nil &&
			h.HealthChecks.Passive != nil &&
			h.HealthChecks.Passive.UnhealthyRequestCount > 0 &&
			upstream.MaxRequests == 0 {
			upstream.MaxRequests = h.HealthChecks.Passive.UnhealthyRequestCount
		}

		// TODO: active health checks

		if h.HealthChecks != nil {
			// upstreams need independent access to the passive
			// health check policy so they can, you know, passively
			// do health checks
			upstream.healthCheckPolicy = h.HealthChecks.Passive
		}
	}

	return nil
}

func (h *Handler) Cleanup() error {
	// TODO: finish this up, make sure it takes care of any active health checkers or whatever
	for _, upstream := range h.Upstreams {
		hosts.Delete(upstream.hostURL.String())
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

		// proxy the request to that upstream
		proxyErr = h.reverseProxy(w, r, upstream)
		if proxyErr == nil {
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
	// ctx := req.Context()
	// TODO: do we need to support CloseNotifier? It was deprecated years ago.
	// All this does is wrap CloseNotify with context cancel, for those responsewriters
	// which didn't support context, but all the ones we'd use should nowadays, right?
	// if cn, ok := rw.(http.CloseNotifier); ok {
	// 	var cancel context.CancelFunc
	// 	ctx, cancel = context.WithCancel(ctx)
	// 	defer cancel()
	// 	notifyChan := cn.CloseNotify()
	// 	go func() {
	// 		select {
	// 		case <-notifyChan:
	// 			cancel()
	// 		case <-ctx.Done():
	// 		}
	// 	}()
	// }

	// TODO: do we need to call WithContext, since we won't be changing req.Context() above if we remove the CloseNotifier stuff?
	// TODO: (This is where references to req were originally "outreq", a shallow clone, which I think is unnecessary in our case)
	// req = req.WithContext(ctx) // includes shallow copies of maps, but okay
	if req.ContentLength == 0 {
		req.Body = nil // Issue golang/go#16036: nil Body for http.Transport retries
	}

	// TODO: is this needed?
	// req.Header = cloneHeader(req.Header)

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

// TODO:
// this code is the entry point to what was borrowed from the net/http/httputil package in the standard library.
func (h *Handler) reverseProxy(rw http.ResponseWriter, req *http.Request, upstream *Upstream) error {
	// TODO: count this active request

	// point the request to this upstream
	h.directRequest(req, upstream)

	// do the round-trip
	start := time.Now()
	res, err := h.Transport.RoundTrip(req)
	latency := time.Since(start)
	if err != nil {
		return err
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
	target := upstream.hostURL
	req.URL.Scheme = target.Scheme
	req.URL.Host = target.Host
	req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path) // TODO: This might be a bug (if any part of the path was augmented from a previously-tried upstream; need to start from clean original path of request, same for query string!)
	if target.RawQuery == "" || req.URL.RawQuery == "" {
		req.URL.RawQuery = target.RawQuery + req.URL.RawQuery
	} else {
		req.URL.RawQuery = target.RawQuery + "&" + req.URL.RawQuery
	}
}

func (h Handler) handleUpgradeResponse(rw http.ResponseWriter, req *http.Request, res *http.Response) {
	reqUpType := upgradeType(req.Header)
	resUpType := upgradeType(res.Header)
	if reqUpType != resUpType {
		// p.getErrorHandler()(rw, req, fmt.Errorf("backend tried to switch protocol %q when %q was requested", resUpType, reqUpType))
		return
	}

	copyHeader(res.Header, rw.Header())

	hj, ok := rw.(http.Hijacker)
	if !ok {
		// p.getErrorHandler()(rw, req, fmt.Errorf("can't switch protocols using non-Hijacker ResponseWriter type %T", rw))
		return
	}
	backConn, ok := res.Body.(io.ReadWriteCloser)
	if !ok {
		// p.getErrorHandler()(rw, req, fmt.Errorf("internal error: 101 switching protocols response with non-writable body"))
		return
	}
	defer backConn.Close()
	conn, brw, err := hj.Hijack()
	if err != nil {
		// p.getErrorHandler()(rw, req, fmt.Errorf("Hijack failed on protocol switch: %v", err))
		return
	}
	defer conn.Close()
	res.Body = nil // so res.Write only writes the headers; we have res.Body in backConn above
	if err := res.Write(brw); err != nil {
		// p.getErrorHandler()(rw, req, fmt.Errorf("response write: %v", err))
		return
	}
	if err := brw.Flush(); err != nil {
		// p.getErrorHandler()(rw, req, fmt.Errorf("response flush: %v", err))
		return
	}
	errc := make(chan error, 1)
	spc := switchProtocolCopier{user: conn, backend: backConn}
	go spc.copyToBackend(errc)
	go spc.copyFromBackend(errc)
	<-errc
	return
}

// flushInterval returns the p.FlushInterval value, conditionally
// overriding its value for a specific request/response.
func (h Handler) flushInterval(req *http.Request, res *http.Response) time.Duration {
	resCT := res.Header.Get("Content-Type")

	// For Server-Sent Events responses, flush immediately.
	// The MIME type is defined in https://www.w3.org/TR/eventsource/#text-event-stream
	if resCT == "text/event-stream" {
		return -1 // negative means immediately
	}

	// TODO: more specific cases? e.g. res.ContentLength == -1?
	// return h.FlushInterval
	return 0
}

func (h Handler) copyResponse(dst io.Writer, src io.Reader, flushInterval time.Duration) error {
	if flushInterval != 0 {
		if wf, ok := dst.(writeFlusher); ok {
			mlw := &maxLatencyWriter{
				dst:     wf,
				latency: flushInterval,
			}
			defer mlw.stop()
			dst = mlw
		}
	}

	// TODO: Figure out how we want to do this... using custom buffer pool type seems unnecessary
	// or maybe it is, depending on how we want to handle errors,
	// see: https://github.com/golang/go/issues/21814
	// buf := bufPool.Get().(*bytes.Buffer)
	// buf.Reset()
	// defer bufPool.Put(buf)
	// _, err := io.CopyBuffer(dst, src, )
	var buf []byte
	// if h.BufferPool != nil {
	// 	buf = h.BufferPool.Get()
	// 	defer h.BufferPool.Put(buf)
	// }
	_, err := h.copyBuffer(dst, src, buf)
	return err
}

// copyBuffer returns any write errors or non-EOF read errors, and the amount
// of bytes written.
func (h Handler) copyBuffer(dst io.Writer, src io.Reader, buf []byte) (int64, error) {
	if len(buf) == 0 {
		buf = make([]byte, 32*1024)
	}
	var written int64
	for {
		nr, rerr := src.Read(buf)
		if rerr != nil && rerr != io.EOF && rerr != context.Canceled {
			// TODO: this could be useful to know (indeed, it revealed an error in our
			// fastcgi PoC earlier; but it's this single error report here that necessitates
			// a function separate from io.CopyBuffer, since io.CopyBuffer does not distinguish
			// between read or write errors; in a reverse proxy situation, write errors are not
			// something we need to report to the client, but read errors are a problem on our
			// end for sure. so we need to decide what we want.)
			// p.logf("copyBuffer: ReverseProxy read error during body copy: %v", rerr)
		}
		if nr > 0 {
			nw, werr := dst.Write(buf[:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if werr != nil {
				return written, werr
			}
			if nr != nw {
				return written, io.ErrShortWrite
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				rerr = nil
			}
			return written, rerr
		}
	}
}

// countFailure remembers 1 failure for upstream for the
// configured duration. If passive health checks are
// disabled or failure expiry is 0, this is a no-op.
func (h Handler) countFailure(upstream *Upstream) {
	// only count failures if passive health checking is enabled
	// and if failures are configured have a non-zero expiry
	if h.HealthChecks == nil || h.HealthChecks.Passive == nil {
		return
	}
	failDuration := time.Duration(h.HealthChecks.Passive.FailDuration)
	if failDuration == 0 {
		return
	}

	// count failure immediately
	err := upstream.Host.CountFail(1)
	if err != nil {
		log.Printf("[ERROR] proxy: upstream %s: counting failure: %v",
			upstream.hostURL, err)
	}

	// forget it later
	go func(host Host, failDuration time.Duration) {
		time.Sleep(failDuration)
		err := host.CountFail(-1)
		if err != nil {
			log.Printf("[ERROR] proxy: upstream %s: expiring failure: %v",
				upstream.hostURL, err)
		}
	}(upstream.Host, failDuration)
}

type writeFlusher interface {
	io.Writer
	http.Flusher
}

type maxLatencyWriter struct {
	dst     writeFlusher
	latency time.Duration // non-zero; negative means to flush immediately

	mu           sync.Mutex // protects t, flushPending, and dst.Flush
	t            *time.Timer
	flushPending bool
}

func (m *maxLatencyWriter) Write(p []byte) (n int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, err = m.dst.Write(p)
	if m.latency < 0 {
		m.dst.Flush()
		return
	}
	if m.flushPending {
		return
	}
	if m.t == nil {
		m.t = time.AfterFunc(m.latency, m.delayedFlush)
	} else {
		m.t.Reset(m.latency)
	}
	m.flushPending = true
	return
}

func (m *maxLatencyWriter) delayedFlush() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.flushPending { // if stop was called but AfterFunc already started this goroutine
		return
	}
	m.dst.Flush()
	m.flushPending = false
}

func (m *maxLatencyWriter) stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.flushPending = false
	if m.t != nil {
		m.t.Stop()
	}
}

// switchProtocolCopier exists so goroutines proxying data back and
// forth have nice names in stacks.
type switchProtocolCopier struct {
	user, backend io.ReadWriter
}

func (c switchProtocolCopier) copyFromBackend(errc chan<- error) {
	_, err := io.Copy(c.user, c.backend)
	errc <- err
}

func (c switchProtocolCopier) copyToBackend(errc chan<- error) {
	_, err := io.Copy(c.backend, c.user)
	errc <- err
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

type LoadBalancing struct {
	SelectionPolicyRaw json.RawMessage `json:"selection_policy,omitempty"`
	TryDuration        caddy.Duration  `json:"try_duration,omitempty"`
	TryInterval        caddy.Duration  `json:"try_interval,omitempty"`

	SelectionPolicy Selector `json:"-"`
}

type Selector interface {
	Select(HostPool, *http.Request) *Upstream
}

type HealthChecks struct {
	Active  *ActiveHealthChecks  `json:"active,omitempty"`
	Passive *PassiveHealthChecks `json:"passive,omitempty"`
}

type ActiveHealthChecks struct {
	Path         string         `json:"path,omitempty"`
	Port         int            `json:"port,omitempty"`
	Interval     caddy.Duration `json:"interval,omitempty"`
	Timeout      caddy.Duration `json:"timeout,omitempty"`
	MaxSize      int            `json:"max_size,omitempty"`
	ExpectStatus int            `json:"expect_status,omitempty"`
	ExpectBody   string         `json:"expect_body,omitempty"`
}

type PassiveHealthChecks struct {
	MaxFails              int            `json:"max_fails,omitempty"`
	FailDuration          caddy.Duration `json:"fail_duration,omitempty"`
	UnhealthyRequestCount int            `json:"unhealthy_request_count,omitempty"`
	UnhealthyStatus       []int          `json:"unhealthy_status,omitempty"`
	UnhealthyLatency      caddy.Duration `json:"unhealthy_latency,omitempty"`
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

var bufPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

//////////////////////////////////
// TODO:

type Host interface {
	NumRequests() int
	Fails() int
	Unhealthy() bool

	CountRequest(int) error
	CountFail(int) error
}

type HostPool []*Upstream

type upstreamHost struct {
	numRequests int64 // must be first field to be 64-bit aligned on 32-bit systems (see https://golang.org/pkg/sync/atomic/#pkg-note-BUG)
	fails       int64
	unhealthy   int32
}

func (uh upstreamHost) NumRequests() int {
	return int(atomic.LoadInt64(&uh.numRequests))
}
func (uh upstreamHost) Fails() int {
	return int(atomic.LoadInt64(&uh.fails))
}
func (uh upstreamHost) Unhealthy() bool {
	return atomic.LoadInt32(&uh.unhealthy) == 1
}
func (uh *upstreamHost) CountRequest(delta int) error {
	result := atomic.AddInt64(&uh.numRequests, int64(delta))
	if result < 0 {
		return fmt.Errorf("count below 0: %d", result)
	}
	return nil
}
func (uh *upstreamHost) CountFail(delta int) error {
	result := atomic.AddInt64(&uh.fails, int64(delta))
	if result < 0 {
		return fmt.Errorf("count below 0: %d", result)
	}
	return nil
}

type Upstream struct {
	Host `json:"-"`

	Address     string `json:"address,omitempty"`
	MaxRequests int    `json:"max_requests,omitempty"`

	// TODO: This could be really cool, to say that requests with
	// certain headers or from certain IPs always go to this upstream
	// HeaderAffinity string
	// IPAffinity     string

	healthCheckPolicy *PassiveHealthChecks

	hostURL *url.URL
}

func (u Upstream) Available() bool {
	return u.Healthy() && !u.Full()
}

func (u Upstream) Healthy() bool {
	healthy := !u.Host.Unhealthy()
	if healthy && u.healthCheckPolicy != nil {
		healthy = u.Host.Fails() < u.healthCheckPolicy.MaxFails
	}
	return healthy
}

func (u Upstream) Full() bool {
	return u.MaxRequests > 0 && u.Host.NumRequests() >= u.MaxRequests
}

func (u Upstream) URL() *url.URL {
	return u.hostURL
}

var hosts = caddy.NewUsagePool()

// TODO: ...
type UpstreamProvider interface {
}

// Interface guards
var (
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.CleanerUpper          = (*Handler)(nil)
)
