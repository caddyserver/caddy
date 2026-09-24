package reverseproxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// TestTruncatedResponse verifies behavior when an upstream sends headers
// (e.g. Content-Length: 500) but closes connection before sending body (Issue #7845).
func TestTruncatedResponse(t *testing.T) {
	// Upstream 1: Sends headers with Content-Length: 500, but immediately terminates
	// before writing any body bytes.
	headerOnlyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "500")
		w.WriteHeader(http.StatusOK)
		_ = http.NewResponseController(w).Flush()
		panic(http.ErrAbortHandler)
	}))
	t.Cleanup(headerOnlyServer.Close)

	// Upstream 2: Healthy server returning 200 OK with body.
	goodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("healthy response"))
	}))
	t.Cleanup(goodServer.Close)

	t.Run("header only returns 502 without panic", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("unexpected panic in ServeHTTP: %v", r)
			}
		}()

		upstreams := []*Upstream{
			{Host: new(Host), Dial: headerOnlyServer.Listener.Addr().String()},
		}
		h := minimalHandler(0, upstreams...)

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

		if gotStatus != http.StatusBadGateway {
			t.Errorf("expected status %d (Bad Gateway), got %d (err: %v)", http.StatusBadGateway, gotStatus, err)
		}
	})

	t.Run("header only does not silently retry to next upstream", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("unexpected panic in ServeHTTP: %v", r)
			}
		}()

		// RoundRobinSelection selects index 1 then index 0.
		// Put goodServer at 0, headerOnlyServer at 1.
		upstreams := []*Upstream{
			{Host: new(Host), Dial: goodServer.Listener.Addr().String()},
			{Host: new(Host), Dial: headerOnlyServer.Listener.Addr().String()},
		}
		h := minimalHandler(1, upstreams...)

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

		// Since upstream already sent headers, the request may have had side effects.
		// Reverseproxy must not silently retry across upstreams (wrapped in roundtripSucceededError),
		// and must cleanly return 502 without having flushed downstream headers.
		if gotStatus != http.StatusBadGateway {
			t.Errorf("expected status %d (Bad Gateway) without retry, got %d (err: %v)", http.StatusBadGateway, gotStatus, err)
		}
		if rec.Flushed {
			t.Errorf("expected downstream response to not be flushed")
		}
	})

	t.Run("both upstreams truncated returns 502", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("unexpected panic in ServeHTTP: %v", r)
			}
		}()

		headerOnlyServer2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "500")
			w.WriteHeader(http.StatusOK)
			_ = http.NewResponseController(w).Flush()
			panic(http.ErrAbortHandler)
		}))
		t.Cleanup(headerOnlyServer2.Close)

		upstreams := []*Upstream{
			{Host: new(Host), Dial: headerOnlyServer.Listener.Addr().String()},
			{Host: new(Host), Dial: headerOnlyServer2.Listener.Addr().String()},
		}
		h := minimalHandler(1, upstreams...)

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

		if gotStatus != http.StatusBadGateway {
			t.Errorf("expected status %d (Bad Gateway) when both upstreams truncate, got %d (err: %v)", http.StatusBadGateway, gotStatus, err)
		}
		if rec.Flushed {
			t.Errorf("expected downstream response to not be flushed when all upstreams truncate")
		}
	})

	t.Run("clean response with Content-Length 0", func(t *testing.T) {
		emptyBodyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "0")
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(emptyBodyServer.Close)

		upstreams := []*Upstream{
			{Host: new(Host), Dial: emptyBodyServer.Listener.Addr().String()},
		}
		h := minimalHandler(0, upstreams...)

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
			t.Errorf("expected status 200, got %d", rec.Code)
		}
	})

	t.Run("clean response with full body", func(t *testing.T) {
		fullBodyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "11")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "hello world")
		}))
		t.Cleanup(fullBodyServer.Close)

		upstreams := []*Upstream{
			{Host: new(Host), Dial: fullBodyServer.Listener.Addr().String()},
		}
		h := minimalHandler(0, upstreams...)

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
			t.Errorf("expected status 200, got %d", rec.Code)
		}
		if rec.Body.String() != "hello world" {
			t.Errorf("expected body 'hello world', got %q", rec.Body.String())
		}
	})

	t.Run("partial body flushes and aborts stream", func(t *testing.T) {
		partialBodyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "500")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "partial")
			_ = http.NewResponseController(w).Flush()
			panic(http.ErrAbortHandler)
		}))
		t.Cleanup(partialBodyServer.Close)

		upstreams := []*Upstream{
			{Host: new(Host), Dial: partialBodyServer.Listener.Addr().String()},
		}
		h := minimalHandler(0, upstreams...)

		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		req = prepareTestRequest(req)

		rec := httptest.NewRecorder()

		var panicked any
		func() {
			defer func() {
				panicked = recover()
			}()
			_ = h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				return nil
			}))
		}()

		if panicked != http.ErrAbortHandler {
			t.Errorf("expected panic ErrAbortHandler for partial body, got %v", panicked)
		}
		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200 wrote before abort, got %d", rec.Code)
		}
		if rec.Body.String() != "partial" {
			t.Errorf("expected partial body 'partial' flushed, got %q", rec.Body.String())
		}
		if !rec.Flushed {
			t.Errorf("expected response to be flushed before stream abort")
		}
	})

	t.Run("delayed fixed length response succeeds", func(t *testing.T) {
		delayedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "11")
			w.WriteHeader(http.StatusOK)
			time.Sleep(50 * time.Millisecond)
			_, _ = io.WriteString(w, "hello world")
		}))
		t.Cleanup(delayedServer.Close)

		upstreams := []*Upstream{
			{Host: new(Host), Dial: delayedServer.Listener.Addr().String()},
		}
		h := minimalHandler(0, upstreams...)

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
			t.Errorf("expected status 200, got %d", rec.Code)
		}
		if rec.Body.String() != "hello world" {
			t.Errorf("expected body 'hello world', got %q", rec.Body.String())
		}
	})

	t.Run("chunked streaming delays first chunk without error", func(t *testing.T) {
		chunkedDelayedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Transfer-Encoding", "chunked")
			w.WriteHeader(http.StatusOK)
			_ = http.NewResponseController(w).Flush()
			time.Sleep(50 * time.Millisecond)
			_, _ = io.WriteString(w, "streamed")
		}))
		t.Cleanup(chunkedDelayedServer.Close)

		upstreams := []*Upstream{
			{Host: new(Host), Dial: chunkedDelayedServer.Listener.Addr().String()},
		}
		h := minimalHandler(0, upstreams...)

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
			t.Errorf("expected status 200, got %d", rec.Code)
		}
		if rec.Body.String() != "streamed" {
			t.Errorf("expected body 'streamed', got %q", rec.Body.String())
		}
	})
}
