package reverseproxy

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// TestTruncatedResponseHeaderOnly verifies that when the upstream sends
// response headers with a Content-Length but closes the connection before
// sending any body, the client still receives the response headers (status
// code and headers) instead of an empty/aborted connection.
// See https://github.com/caddyserver/caddy/issues/7845
func TestTruncatedResponseHeaderOnly(t *testing.T) {
	// backend that sends headers with Content-Length but no body, then aborts
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "500")
		w.Header().Set("X-Custom-Header", "test-value")
		w.WriteHeader(http.StatusInternalServerError)
		// flush headers to the network, then abort — mimicking an upstream
		// that sends headers but closes before the body
		http.NewResponseController(w).Flush()
		panic(http.ErrAbortHandler)
	}))
	defer backend.Close()

	h := minimalHandler(0, &Upstream{
		Host: new(Host),
		Dial: backend.Listener.Addr().String(),
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req = prepareTestRequest(req)

	rec := caddyhttp.NewResponseRecorder(httptest.NewRecorder(), nil, nil)

	// should not panic; instead, headers and status should be propagated
	err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		return nil
	}))

	// we expect an error (incomplete response), but it should be a
	// roundtripSucceededError since headers were received from upstream
	if err == nil {
		t.Error("expected an error from truncated upstream response, got nil")
	}
	var succ roundtripSucceededError
	if !errors.As(err, &succ) {
		t.Errorf("expected roundtripSucceededError (or wrapping it), got %T: %v", err, err)
	}

	// status code should be what the upstream sent
	if got := rec.Status(); got != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", got, http.StatusInternalServerError)
	}

	// custom header should be forwarded
	if got := rec.Header().Get("X-Custom-Header"); got != "test-value" {
		t.Errorf("X-Custom-Header = %q, want %q", got, "test-value")
	}

	// body should be empty (upstream sent none)
	if got := rec.Buffer().Len(); got != 0 {
		t.Errorf("body length = %d, want 0", got)
	}
}

// TestTruncatedResponsePartialBody verifies that when the upstream sends
// a partial body before closing the connection, the client receives the
// status code, headers, and the partial body data.
// See https://github.com/caddyserver/caddy/issues/7845
func TestTruncatedResponsePartialBody(t *testing.T) {
	// backend that sends headers + partial body, then aborts
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "500")
		w.Header().Set("X-Custom-Header", "test-value")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "partial data")
		http.NewResponseController(w).Flush()
		panic(http.ErrAbortHandler)
	}))
	defer backend.Close()

	h := minimalHandler(0, &Upstream{
		Host: new(Host),
		Dial: backend.Listener.Addr().String(),
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req = prepareTestRequest(req)

	rec := caddyhttp.NewResponseRecorder(httptest.NewRecorder(), nil, nil)

	// should not panic
	err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		return nil
	}))

	if err == nil {
		t.Error("expected an error from truncated upstream response, got nil")
	}
	var succ roundtripSucceededError
	if !errors.As(err, &succ) {
		t.Errorf("expected roundtripSucceededError (or wrapping it), got %T: %v", err, err)
	}

	if got := rec.Status(); got != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", got, http.StatusInternalServerError)
	}

	if got := rec.Header().Get("X-Custom-Header"); got != "test-value" {
		t.Errorf("X-Custom-Header = %q, want %q", got, "test-value")
	}

	// body should contain the partial data that was sent
	body := rec.Buffer().String()
	if body != "partial data" {
		t.Errorf("body = %q, want %q", body, "partial data")
	}
}
