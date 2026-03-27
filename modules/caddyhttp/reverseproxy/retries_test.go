package reverseproxy

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
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
