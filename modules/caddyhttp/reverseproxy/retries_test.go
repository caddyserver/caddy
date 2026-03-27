package reverseproxy

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// prepareTestRequest injects the context values that ServeHTTP and
// proxyLoopIteration require (caddy.ReplacerCtxKey, VarsCtxKey, etc.) using
// the same helper that the real HTTP server uses.
//
// A zero-value Server is passed so that caddyhttp.ServerCtxKey is set to a
// non-nil pointer; reverseProxy dereferences it to check ShouldLogCredentials.
func prepareTestRequest(req *http.Request) *http.Request {
	repl := caddy.NewReplacer()
	return caddyhttp.PrepareRequest(req, repl, nil, &caddyhttp.Server{})
}

// closeOnCloseReader is an io.ReadCloser whose Close method actually makes
// subsequent reads fail, mimicking the behaviour of a real HTTP request body
// (as opposed to io.NopCloser, whose Close is a no-op and would mask the bug
// we are testing).
type closeOnCloseReader struct {
	mu     sync.Mutex
	r      *strings.Reader
	closed bool
}

func newCloseOnCloseReader(s string) *closeOnCloseReader {
	return &closeOnCloseReader{r: strings.NewReader(s)}
}

func (c *closeOnCloseReader) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, errors.New("http: invalid Read on closed Body")
	}
	return c.r.Read(p)
}

func (c *closeOnCloseReader) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

// deadUpstreamAddr returns a TCP address that is guaranteed to refuse
// connections: we bind a listener, note its address, close it immediately,
// and return the address. Any dial to that address will get ECONNREFUSED.
func deadUpstreamAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create dead upstream listener: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// testTransport wraps http.Transport to:
//  1. Set the URL scheme to "http" when it is empty (matching what
//     HTTPTransport.SetScheme does in production; cloneRequest strips the
//     scheme intentionally so a plain *http.Transport would fail with
//     "unsupported protocol scheme").
//  2. Wrap dial errors as DialError so that tryAgain correctly identifies them
//     as safe-to-retry regardless of request method (as HTTPTransport does in
//     production via its custom dialer).
type testTransport struct{ *http.Transport }

func (t testTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}
	resp, err := t.Transport.RoundTrip(req)
	if err != nil {
		// Wrap dial errors as DialError to match production behaviour.
		// Without this wrapping, tryAgain treats ECONNREFUSED on a POST
		// request as non-retryable (only GET is retried by default when
		// the error is not a DialError).
		var opErr *net.OpError
		if errors.As(err, &opErr) && opErr.Op == "dial" {
			return nil, DialError{err}
		}
	}
	return resp, err
}

// minimalHandler returns a Handler with only the fields required by ServeHTTP
// set directly, bypassing Provision (which requires a full Caddy runtime).
// RoundRobinSelection is used so that successive iterations of the proxy loop
// advance through the upstream pool in a predictable order.
func minimalHandler(retries int, upstreams ...*Upstream) *Handler {
	return &Handler{
		logger:    zap.NewNop(),
		Transport: testTransport{&http.Transport{}},
		Upstreams: upstreams,
		LoadBalancing: &LoadBalancing{
			Retries:         retries,
			SelectionPolicy: &RoundRobinSelection{},
			// RetryMatch intentionally nil: dial errors are always retried
			// regardless of RetryMatch or request method.
		},
		// ctx, connections, connectionsMu, events: zero/nil values are safe
		// for the code paths exercised by these tests (TryInterval=0 so
		// ctx.Done() is never consulted; no WebSocket hijacking; no passive
		// health-check event emission).
	}
}

// TestDialErrorBodyRetry verifies that a POST request whose body has NOT been
// pre-buffered via request_buffers can still be retried after a dial error.
//
// Before the fix, a dial error caused Go's transport to close the shared body
// (via cloneRequest's shallow copy), so the retry attempt would read from an
// already-closed io.ReadCloser and produce:
//
//	http: invalid Read on closed Body → HTTP 502
//
// After the fix the handler wraps the body in noCloseBody when retries are
// configured, preventing the transport's Close() from propagating to the
// shared body. Since dial errors never read any bytes, the body remains at
// position 0 for the retry.
func TestDialErrorBodyRetry(t *testing.T) {
	// Good upstream: echoes the request body with 200 OK.
	goodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	t.Cleanup(goodServer.Close)

	const requestBody = "hello, retry"

	tests := []struct {
		name       string
		method     string
		body       string
		retries    int
		wantStatus int
		wantBody   string
	}{
		{
			// Core regression case: POST with a body, no request_buffers,
			// dial error on first upstream → retry to second upstream succeeds.
			name:       "POST body retried after dial error",
			method:     http.MethodPost,
			body:       requestBody,
			retries:    1,
			wantStatus: http.StatusOK,
			wantBody:   requestBody,
		},
		{
			// Dial errors are always retried regardless of method, but there
			// is no body to re-read, so GET has always worked. Keep it as a
			// sanity check that we did not break the no-body path.
			name:       "GET without body retried after dial error",
			method:     http.MethodGet,
			body:       "",
			retries:    1,
			wantStatus: http.StatusOK,
			wantBody:   "",
		},
		{
			// Without any retry configuration the handler must give up on the
			// first dial error and return a 502. Confirms no wrapping occurs
			// in the no-retry path.
			name:       "no retries configured returns 502 on dial error",
			method:     http.MethodPost,
			body:       requestBody,
			retries:    0,
			wantStatus: http.StatusBadGateway,
			wantBody:   "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dead := deadUpstreamAddr(t)

			// Build the upstream pool. RoundRobinSelection starts its
			// counter at 0 and increments before returning, so with a
			// two-element pool it picks index 1 first, then index 0.
			// Put the good upstream at index 0 and the dead one at
			// index 1 so that:
			//   attempt 1 → pool[1] = dead → DialError (ECONNREFUSED)
			//   attempt 2 → pool[0] = good → 200
			upstreams := []*Upstream{
				{Host: new(Host), Dial: goodServer.Listener.Addr().String()},
				{Host: new(Host), Dial: dead},
			}
			if tc.retries == 0 {
				// For the "no retries" case use only the dead upstream so
				// there is nowhere to retry to.
				upstreams = []*Upstream{
					{Host: new(Host), Dial: dead},
				}
			}

			h := minimalHandler(tc.retries, upstreams...)

			// Use closeOnCloseReader so that Close() truly prevents further
			// reads, matching real http.body semantics. io.NopCloser would
			// mask the bug because its Close is a no-op.
			var bodyReader io.ReadCloser
			if tc.body != "" {
				bodyReader = newCloseOnCloseReader(tc.body)
			}
			req := httptest.NewRequest(tc.method, "http://example.com/", bodyReader)
			if bodyReader != nil {
				// httptest.NewRequest wraps the reader in NopCloser; replace
				// it with our close-aware reader so Close() is propagated.
				req.Body = bodyReader
				req.ContentLength = int64(len(tc.body))
			}
			req = prepareTestRequest(req)

			rec := httptest.NewRecorder()
			err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				return nil
			}))

			// For error cases (e.g. 502) ServeHTTP returns a HandlerError
			// rather than writing the status itself.
			gotStatus := rec.Code
			if err != nil {
				if herr, ok := err.(caddyhttp.HandlerError); ok {
					gotStatus = herr.StatusCode
				}
			}

			if gotStatus != tc.wantStatus {
				t.Errorf("status: got %d, want %d (err=%v)", gotStatus, tc.wantStatus, err)
			}
			if tc.wantBody != "" && rec.Body.String() != tc.wantBody {
				t.Errorf("body: got %q, want %q", rec.Body.String(), tc.wantBody)
			}
		})
	}
}

// placeholderMatcher is a test-only RequestMatcherWithError that checks
// a Caddy replacer placeholder against a set of allowed values. This
// lets us test the response-retry mechanism without needing to provision
// a full CEL expression matcher (which requires a Caddy context)
type placeholderMatcher struct {
	placeholder string
	values      []any
}

func (m placeholderMatcher) CanMatchResponse() {}

func (m placeholderMatcher) MatchWithError(req *http.Request) (bool, error) {
	repl, ok := req.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if !ok || repl == nil {
		return false, nil
	}
	val, _ := repl.Get(m.placeholder)
	for _, v := range m.values {
		if fmt.Sprint(val) == fmt.Sprint(v) {
			return true, nil
		}
	}
	return false, nil
}

// minimalHandlerWithRetryMatch is like minimalHandler but also configures
// RetryMatch so that response-based retry can be tested
func minimalHandlerWithRetryMatch(retries int, retryMatch caddyhttp.MatcherSets, upstreams ...*Upstream) *Handler {
	h := minimalHandler(retries, upstreams...)
	h.LoadBalancing.RetryMatch = retryMatch
	return h
}

// TestResponseRetryStatusCode verifies that when an upstream returns a status
// code matching a retry_match entry, the request is retried on the next
// upstream. The retry match uses a placeholder matcher on
// http.reverse_proxy.status_code which is how CEL expression matchers access
// the response status at runtime
func TestResponseRetryStatusCode(t *testing.T) {
	var badHits atomic.Int32

	// Bad upstream: returns 502
	badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		badHits.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(badServer.Close)

	// Good upstream: returns 200
	goodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	t.Cleanup(goodServer.Close)

	tests := []struct {
		name        string
		matchCodes  []any
		wantStatus  int
		wantRetried bool // whether a retry should have happened
	}{
		{
			name:        "502 matches retry_match - retries to good upstream",
			matchCodes:  []any{502, 503},
			wantStatus:  http.StatusOK,
			wantRetried: true,
		},
		{
			name:        "404 does not match retry_match - returns 404",
			matchCodes:  []any{502, 503},
			wantStatus:  http.StatusNotFound,
			wantRetried: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			badHits.Store(0)

			retryMatch := caddyhttp.MatcherSets{
				caddyhttp.MatcherSet{
					placeholderMatcher{
						placeholder: "http.reverse_proxy.status_code",
						values:      tc.matchCodes,
					},
				},
			}

			// Determine the bad upstream response code
			var badUpstream *httptest.Server
			if !tc.wantRetried {
				// For the non-match case, use a server returning 404
				badUpstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					badHits.Add(1)
					w.WriteHeader(http.StatusNotFound)
				}))
				t.Cleanup(badUpstream.Close)
			} else {
				badUpstream = badServer
			}

			// RoundRobin picks index 1 first, then 0
			upstreams := []*Upstream{
				{Host: new(Host), Dial: goodServer.Listener.Addr().String()},
				{Host: new(Host), Dial: badUpstream.Listener.Addr().String()},
			}

			h := minimalHandlerWithRetryMatch(1, retryMatch, upstreams...)

			req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
			req = prepareTestRequest(req)
			rec := httptest.NewRecorder()

			err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				return nil
			}))

			gotStatus := rec.Code
			if err != nil {
				if herr, ok := err.(caddyhttp.HandlerError); ok {
					gotStatus = herr.StatusCode
				}
			}

			if gotStatus != tc.wantStatus {
				t.Errorf("status: got %d, want %d (err=%v)", gotStatus, tc.wantStatus, err)
			}

			if tc.wantRetried && badHits.Load() != 1 {
				t.Errorf("bad upstream hits: got %d, want 1", badHits.Load())
			}
		})
	}
}

// TestResponseRetryHeader verifies that response header matching triggers
// retries. The retry match checks http.reverse_proxy.header.X-Upstream-Retry
// which is how CEL expressions like {rp.header.X-Upstream-Retry} access
// response headers at runtime
func TestResponseRetryHeader(t *testing.T) {
	// Bad upstream: returns 200 but with X-Upstream-Retry header
	badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream-Retry", "true")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("bad"))
	}))
	t.Cleanup(badServer.Close)

	// Good upstream: returns 200 without retry header
	goodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("good"))
	}))
	t.Cleanup(goodServer.Close)

	retryMatch := caddyhttp.MatcherSets{
		caddyhttp.MatcherSet{
			placeholderMatcher{
				placeholder: "http.reverse_proxy.header.X-Upstream-Retry",
				values:      []any{"true"},
			},
		},
	}

	// RoundRobin picks index 1 first, then 0
	upstreams := []*Upstream{
		{Host: new(Host), Dial: goodServer.Listener.Addr().String()},
		{Host: new(Host), Dial: badServer.Listener.Addr().String()},
	}

	h := minimalHandlerWithRetryMatch(1, retryMatch, upstreams...)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req = prepareTestRequest(req)
	rec := httptest.NewRecorder()

	err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusOK)
	}
	if rec.Body.String() != "good" {
		t.Errorf("body: got %q, want %q (retried to wrong upstream)", rec.Body.String(), "good")
	}
}

// TestResponseRetryNoMatchNoRetry verifies that when no retry_match entries
// match the response, the original response is returned without retrying
func TestResponseRetryNoMatchNoRetry(t *testing.T) {
	var hits atomic.Int32

	// Server that returns 500 - but retry_match only matches 502/503
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)

	retryMatch := caddyhttp.MatcherSets{
		caddyhttp.MatcherSet{
			placeholderMatcher{
				placeholder: "http.reverse_proxy.status_code",
				values:      []any{502, 503},
			},
		},
	}

	upstreams := []*Upstream{
		{Host: new(Host), Dial: server.Listener.Addr().String()},
		{Host: new(Host), Dial: server.Listener.Addr().String()},
	}

	h := minimalHandlerWithRetryMatch(2, retryMatch, upstreams...)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req = prepareTestRequest(req)
	rec := httptest.NewRecorder()

	_ = h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}))

	// Only one hit - no retry since 500 doesn't match [502, 503]
	if hits.Load() != 1 {
		t.Errorf("upstream hits: got %d, want 1 (should not have retried)", hits.Load())
	}
}

// TestResponseRetryExhaustedPreservesStatusCode verifies that when retries
// are exhausted, the actual upstream status code (e.g. 503) is reported
// to the client, not a generic 502
func TestResponseRetryExhaustedPreservesStatusCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable) // 503
	}))
	t.Cleanup(server.Close)

	retryMatch := caddyhttp.MatcherSets{
		caddyhttp.MatcherSet{
			placeholderMatcher{
				placeholder: "http.reverse_proxy.status_code",
				values:      []any{503},
			},
		},
	}

	upstreams := []*Upstream{
		{Host: new(Host), Dial: server.Listener.Addr().String()},
		{Host: new(Host), Dial: server.Listener.Addr().String()},
	}

	h := minimalHandlerWithRetryMatch(1, retryMatch, upstreams...)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req = prepareTestRequest(req)
	rec := httptest.NewRecorder()

	err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}))

	gotStatus := rec.Code
	if err != nil {
		if herr, ok := err.(caddyhttp.HandlerError); ok {
			gotStatus = herr.StatusCode
		}
	}

	// Must return 503 (actual upstream status), not 502 (generic proxy error)
	if gotStatus != http.StatusServiceUnavailable {
		t.Errorf("status: got %d, want %d (status code not preserved)", gotStatus, http.StatusServiceUnavailable)
	}
}

// TestResponseRetryHeaderCleanup verifies that stale response header
// placeholders from a previous upstream attempt are cleaned up before the
// next retry evaluation. Without cleanup, a header like X-Retry: true from
// upstream A would leak into the retry match for upstream B even if B does
// not set that header
func TestResponseRetryHeaderCleanup(t *testing.T) {
	// First upstream: returns 200 with X-Retry header (triggers retry)
	firstServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Retry", "true")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("first"))
	}))
	t.Cleanup(firstServer.Close)

	// Second upstream: returns 200 WITHOUT X-Retry header (should NOT retry)
	secondServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("second"))
	}))
	t.Cleanup(secondServer.Close)

	retryMatch := caddyhttp.MatcherSets{
		caddyhttp.MatcherSet{
			placeholderMatcher{
				placeholder: "http.reverse_proxy.header.X-Retry",
				values:      []any{"true"},
			},
		},
	}

	// RoundRobin picks index 1 first, then 0
	upstreams := []*Upstream{
		{Host: new(Host), Dial: secondServer.Listener.Addr().String()},
		{Host: new(Host), Dial: firstServer.Listener.Addr().String()},
	}

	h := minimalHandlerWithRetryMatch(2, retryMatch, upstreams...)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req = prepareTestRequest(req)
	rec := httptest.NewRecorder()

	err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should get "second" - the first upstream's X-Retry header must not
	// leak into the second upstream's retry evaluation
	if rec.Body.String() != "second" {
		t.Errorf("body: got %q, want %q (stale header leaked between retries)", rec.Body.String(), "second")
	}
}

// TestRequestOnlyMatcherDoesNotRetryResponses verifies that a pure request
// matcher like method PUT in lb_retry_match does NOT trigger response-based
// retries. Only expression matchers (which can reference response data)
// should trigger response retries
func TestRequestOnlyMatcherDoesNotRetryResponses(t *testing.T) {
	var hits atomic.Int32

	// Server returns 200 OK for all requests
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	t.Cleanup(server.Close)

	// method PUT matcher - should NOT trigger response retries
	retryMatch := caddyhttp.MatcherSets{
		caddyhttp.MatcherSet{
			caddyhttp.MatchMethod{"PUT"},
		},
	}

	upstreams := []*Upstream{
		{Host: new(Host), Dial: server.Listener.Addr().String()},
		{Host: new(Host), Dial: server.Listener.Addr().String()},
	}

	h := minimalHandlerWithRetryMatch(2, retryMatch, upstreams...)

	req := httptest.NewRequest(http.MethodPut, "http://example.com/", nil)
	req = prepareTestRequest(req)
	rec := httptest.NewRecorder()

	err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should hit only once - no retry for 200 OK even though method matches
	if hits.Load() != 1 {
		t.Errorf("upstream hits: got %d, want 1 (should not retry successful responses)", hits.Load())
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusOK)
	}
}

// brokenUpstreamAddr returns the address of a TCP listener that accepts
// connections but immediately closes them, causing a transport error (not
// a dial error). This simulates an upstream that is reachable but broken
func brokenUpstreamAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	return ln.Addr().String()
}

// TestTransportErrorPlaceholder verifies that the is_transport_error
// placeholder is set to true during transport error evaluation in tryAgain()
// and that expression matchers using isTransportError() can match it
func TestTransportErrorPlaceholder(t *testing.T) {
	broken := brokenUpstreamAddr(t)

	goodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	t.Cleanup(goodServer.Close)

	// Matcher that checks the is_transport_error placeholder -
	// simulates what isTransportError() does in CEL
	retryMatch := caddyhttp.MatcherSets{
		caddyhttp.MatcherSet{
			placeholderMatcher{
				placeholder: "http.reverse_proxy.is_transport_error",
				values:      []any{true},
			},
		},
	}

	// RoundRobin picks index 1 first (broken), then 0 (good)
	upstreams := []*Upstream{
		{Host: new(Host), Dial: goodServer.Listener.Addr().String()},
		{Host: new(Host), Dial: broken},
	}

	h := minimalHandlerWithRetryMatch(1, retryMatch, upstreams...)

	req := httptest.NewRequest(http.MethodPost, "http://example.com/", nil)
	req = prepareTestRequest(req)
	rec := httptest.NewRecorder()

	err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}))

	gotStatus := rec.Code
	if err != nil {
		if herr, ok := err.(caddyhttp.HandlerError); ok {
			gotStatus = herr.StatusCode
		}
	}

	// POST transport error should be retried because is_transport_error matched
	if gotStatus != http.StatusOK {
		t.Errorf("status: got %d, want %d (transport error should have been retried)", gotStatus, http.StatusOK)
	}
}

// TestTransportErrorPlaceholderNotSetForResponses verifies that the
// is_transport_error placeholder is NOT set when evaluating response
// matchers, so isTransportError() returns false for response retries
func TestTransportErrorPlaceholderNotSetForResponses(t *testing.T) {
	var hits atomic.Int32

	// Server returns 502 - but the matcher only checks isTransportError
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(server.Close)

	// Only matches transport errors, not response errors
	retryMatch := caddyhttp.MatcherSets{
		caddyhttp.MatcherSet{
			placeholderMatcher{
				placeholder: "http.reverse_proxy.is_transport_error",
				values:      []any{true},
			},
		},
	}

	upstreams := []*Upstream{
		{Host: new(Host), Dial: server.Listener.Addr().String()},
		{Host: new(Host), Dial: server.Listener.Addr().String()},
	}

	h := minimalHandlerWithRetryMatch(2, retryMatch, upstreams...)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req = prepareTestRequest(req)
	rec := httptest.NewRecorder()

	_ = h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}))

	// Should hit only once - is_transport_error is false during response
	// evaluation so the 502 is NOT retried
	if hits.Load() != 1 {
		t.Errorf("upstream hits: got %d, want 1 (isTransportError should be false for responses)", hits.Load())
	}
}

// TestRetryMatchRejectsExpressionMixedWithOtherMatchers verifies that
// lb_retry_match rejects a block that mixes expression with other matchers
func TestRetryMatchRejectsExpressionMixedWithOtherMatchers(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name: "expression alone is allowed",
			input: `reverse_proxy localhost:9080 {
				lb_retry_match {
					expression ` + "`{rp.status_code} in [502, 503]`" + `
				}
			}`,
			wantErr: false,
		},
		{
			name: "method alone is allowed",
			input: `reverse_proxy localhost:9080 {
				lb_retry_match {
					method PUT
				}
			}`,
			wantErr: false,
		},
		{
			name: "expression mixed with method is rejected",
			input: `reverse_proxy localhost:9080 {
				lb_retry_match {
					method POST
					expression ` + "`{rp.status_code} in [502, 503]`" + `
				}
			}`,
			wantErr: true,
		},
		{
			name: "expression mixed with path is rejected",
			input: `reverse_proxy localhost:9080 {
				lb_retry_match {
					path /api*
					expression ` + "`{rp.status_code} == 502`" + `
				}
			}`,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handler{}
			d := caddyfile.NewTestDispenser(tc.input)
			err := h.UnmarshalCaddyfile(d)
			if tc.wantErr && err == nil {
				t.Error("expected error but got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
