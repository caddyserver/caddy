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

// testProxyStatusName identifies the proxy in Proxy-Status assertions. RFC 9209
// wants the deployment named rather than the software, so the tests configure
// one the way a deployment would.
const testProxyStatusName = "proxy-3.example.com"

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

	want := testProxyStatusName + ";error=" + proxyErrorIncrementalRefused
	if got := hdr.Get("Proxy-Status"); got != want {
		t.Errorf("Proxy-Status = %q, want %q", got, want)
	}
}

// incrementalHandler proxies to backendAddr under a name it can report in a
// Proxy-Status field.
func incrementalHandler(backendAddr string) *Handler {
	h := minimalHandler(0, &Upstream{
		Host: new(Host),
		Dial: backendAddr,
	})
	h.ProxyStatusName = testProxyStatusName

	return h
}

// incrementalRequest builds a request marked incremental; an unknown length is
// what a chunked request looks like once the server has parsed it.
func incrementalRequest(body string, knownLength bool) *http.Request {
	var r io.Reader = strings.NewReader(body)
	if !knownLength {
		r = io.NopCloser(r) // opaque to httptest, so ContentLength stays -1
	}
	req := httptest.NewRequest(http.MethodPost, "http://example.com/", r)
	req.Header.Set("Incremental", "?1")
	return prepareTestRequest(req)
}

// lengthRequiringTransport stands in for fastcgi, which cannot forward a body
// whose length it does not know.
type lengthRequiringTransport struct{ testTransport }

func (lengthRequiringTransport) RequiresContentLength() bool { return true }

// A bounded buffer forwards once its limit is reached, so it holds back a body
// of unknown length no more than any other: RFC 10036 section 4.3 allows it.
func TestIncrementalProxiedWhenRequestLengthUnknown(t *testing.T) {
	var gotBody string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
	}))
	defer backend.Close()

	h := incrementalHandler(backend.Listener.Addr().String())
	h.RequestBuffers = 4096

	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, incrementalRequest("hello", false), caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		return nil
	})); err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}

	if gotBody != "hello" {
		t.Errorf("upstream body = %q, want %q", gotBody, "hello")
	}
}

// A transport that needs a CONTENT_LENGTH is the exception: only buffering the
// body in full can supply one, which is what incremental forwarding rules out.
func TestIncrementalRefusedWhenTransportRequiresContentLength(t *testing.T) {
	var reached bool
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))
	defer backend.Close()

	h := incrementalHandler(backend.Listener.Addr().String())
	h.RequestBuffers = 4096
	h.Transport = lengthRequiringTransport{testTransport{&http.Transport{}}}

	rec := httptest.NewRecorder()
	err := h.ServeHTTP(rec, incrementalRequest("hello", false), caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		return nil
	}))

	assertRefused(t, err, rec.Header())
	if reached {
		t.Error("request was forwarded upstream despite being refused")
	}
}

// An unlimited buffer holds the entire body no matter its length, which RFC
// 10036 section 3 forbids for a message marked incremental.
func TestIncrementalRefusedWhenRequestBufferUnlimited(t *testing.T) {
	var reached bool
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))
	defer backend.Close()

	h := incrementalHandler(backend.Listener.Addr().String())
	h.RequestBuffers = -1

	rec := httptest.NewRecorder()
	err := h.ServeHTTP(rec, incrementalRequest("hello", true), caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		return nil
	}))

	assertRefused(t, err, rec.Header())
	if reached {
		t.Error("request was forwarded upstream despite being refused")
	}
}

// A bounded buffer over a body of known length is the small amount of
// buffering RFC 10036 section 4.3 allows: the body ends, so the buffer cannot
// hold it back indefinitely.
func TestIncrementalProxiedWhenRequestLengthKnown(t *testing.T) {
	var gotBody string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
	}))
	defer backend.Close()

	h := incrementalHandler(backend.Listener.Addr().String())
	h.RequestBuffers = 4096

	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, incrementalRequest("hello", true), caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		return nil
	})); err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}

	if gotBody != "hello" {
		t.Errorf("upstream body = %q, want %q", gotBody, "hello")
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

	h := incrementalHandler(backend.Listener.Addr().String())

	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, incrementalRequest("hello", false), caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
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

	h := incrementalHandler(backend.Listener.Addr().String())
	h.RequestBuffers = -1

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

// serveIncremental runs a request marked incremental against a backend whose
// response is also marked incremental.
func serveIncremental(t *testing.T, responseBuffers int64, backendFn http.HandlerFunc) (*httptest.ResponseRecorder, error) {
	t.Helper()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Incremental", "?1")
		backendFn(w, r)
	}))
	t.Cleanup(backend.Close)

	h := incrementalHandler(backend.Listener.Addr().String())
	h.ResponseBuffers = responseBuffers

	req := prepareTestRequest(httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
	rec := httptest.NewRecorder()
	err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		return nil
	}))
	return rec, err
}

// A bounded buffer forwards a response of unknown length the same way it
// forwards any other, so there is nothing to refuse.
func TestIncrementalProxiedWhenResponseLengthUnknown(t *testing.T) {
	rec, err := serveIncremental(t, 4096, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush() // forces chunked, so the length stays unknown
		_, _ = w.Write([]byte("data: hi\n\n"))
	})
	if err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}

	if got := rec.Body.String(); got != "data: hi\n\n" {
		t.Errorf("body = %q, want %q", got, "data: hi\n\n")
	}
}

// An unlimited buffer holds the entire response, whatever its length.
func TestIncrementalRefusedWhenResponseBufferUnlimited(t *testing.T) {
	rec, err := serveIncremental(t, -1, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("data: hi\n\n"))
	})

	assertRefused(t, err, rec.Header())
}

// A bodyless response has no content to forward incrementally, so there is
// nothing to refuse even with buffering configured.
func TestIncrementalProxiedWhenResponseHasNoBody(t *testing.T) {
	rec, err := serveIncremental(t, -1, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	if err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

// A response of known length longer than the buffer is forwarded once the
// byte limit is reached, which is what RFC 10036 section 4.3 requires of a
// bounded buffer, so it is not refused.
func TestIncrementalProxiedWhenResponseExceedsBuffer(t *testing.T) {
	body := strings.Repeat("x", 10000)
	rec, err := serveIncremental(t, 4096, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "10000")
		_, _ = w.Write([]byte(body))
	})
	if err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}

	if got := rec.Body.String(); got != body {
		t.Errorf("body length = %d, want %d", len(got), len(body))
	}
}

// The upstream response is passed through untouched when no response
// buffering is configured.
func TestIncrementalProxiedWhenResponseNotBuffered(t *testing.T) {
	rec, err := serveIncremental(t, 0, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		_, _ = w.Write([]byte("data: hi\n\n"))
	})
	if err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != "data: hi\n\n" {
		t.Errorf("body = %q, want %q", got, "data: hi\n\n")
	}
}

// A software name identifies no deployment, so with nothing configured to
// identify this proxy there is no Proxy-Status field to generate: RFC 9209
// leaves generating it optional.
func TestProxyStatusOmittedWhenUnnamed(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer backend.Close()

	h := incrementalHandler(backend.Listener.Addr().String())
	h.ProxyStatusName = ""
	h.RequestBuffers = -1

	rec := httptest.NewRecorder()
	err := h.ServeHTTP(rec, incrementalRequest("hello", true), caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		return nil
	}))

	var handlerErr caddyhttp.HandlerError
	if !errors.As(err, &handlerErr) || handlerErr.StatusCode != http.StatusNotImplemented {
		t.Fatalf("expected a 501 HandlerError, got %v", err)
	}
	if got, ok := rec.Header()["Proxy-Status"]; ok {
		t.Errorf("Proxy-Status = %q, want no field", got)
	}
}

// RFC 9209 section 2 asks intermediaries to preserve the members already in
// the field, so the whole chain that handled the response stays visible.
func TestProxyStatusPreservesUpstreamMembers(t *testing.T) {
	rec, err := serveIncremental(t, -1, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Proxy-Status", "ExampleCDN")
		_, _ = w.Write([]byte("data: hi\n\n"))
	})

	var handlerErr caddyhttp.HandlerError
	if !errors.As(err, &handlerErr) || handlerErr.StatusCode != http.StatusNotImplemented {
		t.Fatalf("expected a 501 HandlerError, got %v", err)
	}

	want := "ExampleCDN, " + testProxyStatusName + ";error=" + proxyErrorIncrementalRefused
	if got := rec.Header().Get("Proxy-Status"); got != want {
		t.Errorf("Proxy-Status = %q, want %q", got, want)
	}
}

// A name a token cannot hold is quoted as a string instead, which RFC 9209
// allows just as well.
func TestProxyStatusNameNeedingQuotes(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer backend.Close()

	h := incrementalHandler(backend.Listener.Addr().String())
	h.ProxyStatusName = "Example CDN"
	h.RequestBuffers = -1

	rec := httptest.NewRecorder()
	_ = h.ServeHTTP(rec, incrementalRequest("hello", true), caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		return nil
	}))

	want := `"Example CDN";error=` + proxyErrorIncrementalRefused
	if got := rec.Header().Get("Proxy-Status"); got != want {
		t.Errorf("Proxy-Status = %q, want %q", got, want)
	}
}

// HTTP/3 reports a negative length for bodyless GET and HEAD requests (issue
// #6678), which is exactly the case the fastcgi request buffer exists to fix,
// so an unknown length must not be mistaken for content that is still coming.
func TestIncrementalProxiedWhenBodylessRequestHasUnknownLength(t *testing.T) {
	var reached bool
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))
	defer backend.Close()

	h := incrementalHandler(backend.Listener.Addr().String())
	h.RequestBuffers = 4096
	h.Transport = lengthRequiringTransport{testTransport{&http.Transport{}}}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", io.NopCloser(strings.NewReader("")))
	req.Header.Set("Incremental", "?1")
	req = prepareTestRequest(req)
	if req.ContentLength != -1 {
		t.Fatalf("ContentLength = %d, want -1", req.ContentLength)
	}

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

// A response to HEAD advertises the length the content would have had, while
// carrying no content at all, so there is nothing for a buffer to hold back.
func TestIncrementalProxiedWhenHeadResponseAdvertisesLength(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Incremental", "?1")
		w.Header().Set("Content-Length", "10000")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	h := incrementalHandler(backend.Listener.Addr().String())
	h.ResponseBuffers = -1

	req := prepareTestRequest(httptest.NewRequest(http.MethodHead, "http://example.com/", nil))
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		return nil
	})); err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}
