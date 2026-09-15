package reverseproxy

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// assertRefused checks the response of a refused incremental forwarding
// against what RFC 10036 section 4.1 recommends.
func assertRefused(t *testing.T, err error, hdr http.Header) {
	t.Helper()

	var handlerErr caddyhttp.HandlerError
	if !errors.As(err, &handlerErr) {
		t.Fatalf("expected a caddyhttp.HandlerError, got %T: %v", err, err)
	}
	if handlerErr.StatusCode != http.StatusNotImplemented {
		t.Errorf("status = %d, want %d", handlerErr.StatusCode, http.StatusNotImplemented)
	}
	if got := hdr.Get("Proxy-Status"); got != proxyStatusIncrementalRefused {
		t.Errorf("Proxy-Status = %q, want %q", got, proxyStatusIncrementalRefused)
	}
}

// Request buffering is what lets the fastcgi transport send a CONTENT_LENGTH,
// so it cannot be traded away for incremental forwarding. RFC 10036 section 3
// requires refusing rather than buffering a message marked incremental.
func TestIncrementalRefusedWhenRequestBuffered(t *testing.T) {
	var reached bool
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))
	defer backend.Close()

	h := minimalHandler(0, &Upstream{
		Host: new(Host),
		Dial: backend.Listener.Addr().String(),
	})
	h.RequestBuffers = 4096

	req := httptest.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader("hello"))
	req.Header.Set("Incremental", "?1")
	req = prepareTestRequest(req)

	rec := httptest.NewRecorder()
	err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		return nil
	}))

	assertRefused(t, err, rec.Header())
	if reached {
		t.Error("request was forwarded upstream despite being refused")
	}
}

// Without buffering configured there is nothing to refuse, so the request is
// proxied as usual.
func TestIncrementalProxiedWhenRequestNotBuffered(t *testing.T) {
	var gotBody string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
	}))
	defer backend.Close()

	h := minimalHandler(0, &Upstream{
		Host: new(Host),
		Dial: backend.Listener.Addr().String(),
	})

	req := httptest.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader("hello"))
	req.Header.Set("Incremental", "?1")
	req = prepareTestRequest(req)

	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		return nil
	})); err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}

	if gotBody != "hello" {
		t.Errorf("upstream body = %q, want %q", gotBody, "hello")
	}
}

// A bodyless request has no content to forward incrementally, so buffering it
// is a no-op and there is nothing to refuse.
func TestIncrementalProxiedWhenRequestHasNoBody(t *testing.T) {
	var reached bool
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))
	defer backend.Close()

	h := minimalHandler(0, &Upstream{
		Host: new(Host),
		Dial: backend.Listener.Addr().String(),
	})
	h.RequestBuffers = 4096

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("Incremental", "?1")
	req = prepareTestRequest(req)

	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		return nil
	})); err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}

	if !reached {
		t.Error("bodyless request was not forwarded upstream")
	}
}

// Buffering a response marked incremental would stall the client for as long
// as the upstream keeps the stream open, which is the failure RFC 10036 exists
// to prevent, so it is refused too.
func TestIncrementalRefusedWhenResponseBuffered(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Incremental", "?1")
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	h := minimalHandler(0, &Upstream{
		Host: new(Host),
		Dial: backend.Listener.Addr().String(),
	})
	h.ResponseBuffers = 4096

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req = prepareTestRequest(req)

	rec := httptest.NewRecorder()
	err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		return nil
	}))

	assertRefused(t, err, rec.Header())
}

// The upstream response is passed through untouched when no response
// buffering is configured.
func TestIncrementalProxiedWhenResponseNotBuffered(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Incremental", "?1")
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data: hi\n\n"))
	}))
	defer backend.Close()

	h := minimalHandler(0, &Upstream{
		Host: new(Host),
		Dial: backend.Listener.Addr().String(),
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req = prepareTestRequest(req)

	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		return nil
	})); err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != "data: hi\n\n" {
		t.Errorf("body = %q, want %q", got, "data: hi\n\n")
	}
}
