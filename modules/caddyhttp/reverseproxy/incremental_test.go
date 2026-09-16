package reverseproxy

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/headers"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/rewrite"
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

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type lengthRequiringRoundTripFunc roundTripFunc

func (f lengthRequiringRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return roundTripFunc(f)(r)
}

func (lengthRequiringRoundTripFunc) RequiresContentLength() bool { return true }

type stagedBody struct {
	release <-chan struct{}
	sent    bool
}

func (b *stagedBody) Read(p []byte) (int, error) {
	if !b.sent {
		b.sent = true
		p[0] = 'x'
		return 1, nil
	}
	<-b.release
	return 0, io.EOF
}

func (*stagedBody) Close() error { return nil }

// Without buffering or a transport framing conflict, an unknown-length
// incremental request is streamed unchanged.
func TestIncrementalProxiedWhenRequestLengthUnknown(t *testing.T) {
	var gotBody string
	var gotLength int64
	var gotIncremental string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		gotLength = r.ContentLength
		gotIncremental = r.Header.Get("Incremental")
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
	if gotLength != -1 {
		t.Errorf("upstream ContentLength = %d, want -1", gotLength)
	}
	if gotIncremental != "?1" {
		t.Errorf("upstream Incremental = %q, want ?1", gotIncremental)
	}
}

// A transport that needs a CONTENT_LENGTH is the exception: only buffering the
// body in full can supply one, which is what incremental forwarding rules out.
func TestIncrementalRefusedWhenTransportRequiresContentLength(t *testing.T) {
	for _, requestBuffers := range []int64{0, 4096} {
		t.Run(fmt.Sprintf("buffers_%d", requestBuffers), func(t *testing.T) {
			var reached bool
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached = true
			}))
			defer backend.Close()

			h := incrementalHandler(backend.Listener.Addr().String())
			h.RequestBuffers = requestBuffers
			h.Transport = lengthRequiringTransport{testTransport{&http.Transport{}}}

			rec := httptest.NewRecorder()
			err := h.ServeHTTP(rec, incrementalRequest("hello", false), caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
				return nil
			}))

			assertRefused(t, err, rec.Header())
			if reached {
				t.Error("request was forwarded upstream despite being refused")
			}
		})
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

// An explicit buffer is operator policy. An incremental request is refused
// instead of allowing an external header to disable that policy.
func TestIncrementalRefusedWhenRequestBufferConfigured(t *testing.T) {
	h := incrementalHandler("unused.invalid")
	h.RequestBuffers = 4096
	rec := httptest.NewRecorder()
	err := h.ServeHTTP(rec, incrementalRequest("hello", true), caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		return nil
	}))
	assertRefused(t, err, rec.Header())
}

// A transport-supplied buffer that exists only to discover Content-Length is
// unnecessary when the request already has one and must not delay forwarding.
func TestIncrementalKnownLengthRequestBypassesTransportDefault(t *testing.T) {
	release := make(chan struct{})
	reached := make(chan struct{})
	h := incrementalHandler("unused.invalid")
	h.RequestBuffers = 4096
	h.requestBuffersFromTransport = true
	h.Transport = lengthRequiringRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		close(reached)
		return &http.Response{
			StatusCode:    http.StatusOK,
			Status:        "200 OK",
			Header:        make(http.Header),
			Body:          http.NoBody,
			ContentLength: 0,
			Request:       req,
		}, nil
	})
	req := httptest.NewRequest(http.MethodPost, "http://example.com/", &stagedBody{release: release})
	req.ContentLength = 2
	req.Header.Set("Content-Length", "2")
	req.Header.Set("Incremental", "?1")
	req = prepareTestRequest(req)

	done := make(chan error, 1)
	go func() {
		done <- h.ServeHTTP(httptest.NewRecorder(), req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
			return nil
		}))
	}()

	select {
	case <-reached:
	case <-time.After(2 * time.Second):
		t.Error("incremental request remained in the transport's default buffer")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
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

// A configured method rewrite can remove the request content before proxying.
// Refusal is decided after that rewrite rather than from the original request.
func TestIncrementalRewriteRemovesRequestContentBeforeRefusal(t *testing.T) {
	var gotLength int64 = -1
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotLength = r.ContentLength
	}))
	defer backend.Close()

	h := incrementalHandler(backend.Listener.Addr().String())
	h.RequestBuffers = -1
	h.Rewrite = &rewrite.Rewrite{Method: http.MethodGet}

	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, incrementalRequest("hello", true), caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		return nil
	})); err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
	if gotLength != 0 {
		t.Errorf("upstream ContentLength = %d, want 0", gotLength)
	}
}

func TestIncrementalAddedByHeaderUpAfterBufferingIsRefused(t *testing.T) {
	h := incrementalHandler("unused.invalid")
	h.RequestBuffers = 4096
	h.Headers = &headers.Handler{Request: &headers.HeaderOps{
		Set: http.Header{"Incremental": []string{"?1"}},
	}}
	req := incrementalRequest("hello", true)
	req.Header.Del("Incremental")

	rec := httptest.NewRecorder()
	err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		return nil
	}))
	assertRefused(t, err, rec.Header())
}

// serveIncremental runs an ordinary request against a backend whose response
// is marked incremental. Request and response signals are independent.
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

// An explicit response buffer is operator policy. An incremental response is
// refused rather than allowing the upstream to disable that policy.
func TestIncrementalRefusedWhenResponseBufferConfigured(t *testing.T) {
	rec, err := serveIncremental(t, 4096, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush() // forces chunked, so the length stays unknown
		_, _ = w.Write([]byte("data: hi\n\n"))
	})
	assertRefused(t, err, rec.Header())
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
	if got := rec.Header().Get("Incremental"); got != "?1" {
		t.Errorf("downstream Incremental = %q, want ?1", got)
	}
}

// Replacing an upstream response does not forward or buffer its body. The
// replacement remains valid even when that unused response was incremental.
func TestIncrementalResponseCanBeReplaced(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Incremental", "?1")
		_, _ = w.Write([]byte("upstream"))
	}))
	defer backend.Close()

	h := incrementalHandler(backend.Listener.Addr().String())
	h.ResponseBuffers = -1
	h.HandleResponse = []caddyhttp.ResponseHandler{{}}
	req := prepareTestRequest(httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
	rec := httptest.NewRecorder()
	err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		_, writeErr := w.Write([]byte("replacement"))
		return writeErr
	}))
	if err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
	if got := rec.Body.String(); got != "replacement" {
		t.Errorf("body = %q, want %q", got, "replacement")
	}
}

func TestIncrementalAddedByHeaderDownAfterBufferingIsRefused(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello"))
	}))
	defer backend.Close()

	h := incrementalHandler(backend.Listener.Addr().String())
	h.ResponseBuffers = 4096
	h.Headers = &headers.Handler{Response: &headers.RespHeaderOps{HeaderOps: &headers.HeaderOps{
		Set: http.Header{"Incremental": []string{"?1"}},
	}}}
	req := prepareTestRequest(httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
	rec := httptest.NewRecorder()
	err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		return nil
	}))
	assertRefused(t, err, rec.Header())
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

func TestProxyStatusDropsInvalidMembers(t *testing.T) {
	h := &Handler{ProxyStatusName: testProxyStatusName}
	upstream := http.Header{
		"Proxy-Status": []string{"?1, (inner), upstream.example"},
	}

	got, ok := h.proxyStatus(upstream, proxyErrorIncrementalRefused)
	if !ok {
		t.Fatal("proxyStatus() did not produce a value")
	}
	want := testProxyStatusName + ";error=" + proxyErrorIncrementalRefused
	if got != want {
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

// A method does not prove that an unknown-length request has no content.
// Assuming otherwise lets a body reach a transport that cannot forward it.
func TestIncrementalRefusedWhenMethodHasUnknownLengthContent(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodOptions, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			h := incrementalHandler("unused.invalid")
			h.RequestBuffers = 4096
			h.Transport = lengthRequiringTransport{testTransport{&http.Transport{}}}

			req := httptest.NewRequest(method, "http://example.com/", io.NopCloser(strings.NewReader(strings.Repeat("x", 8192))))
			req.Header.Set("Incremental", "?1")
			req = prepareTestRequest(req)

			rec := httptest.NewRecorder()
			err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
				return nil
			}))
			assertRefused(t, err, rec.Header())
		})
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

func TestResponseHasContent(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method string
		status int
		length int64
		body   io.ReadCloser
		want   bool
	}{
		{name: "unknown response", method: http.MethodGet, status: http.StatusOK, length: -1, body: io.NopCloser(strings.NewReader("x")), want: true},
		{name: "HEAD", method: http.MethodHead, status: http.StatusOK, length: 10, body: io.NopCloser(strings.NewReader(""))},
		{name: "informational", method: http.MethodGet, status: http.StatusEarlyHints, length: -1, body: io.NopCloser(strings.NewReader(""))},
		{name: "no content", method: http.MethodGet, status: http.StatusNoContent, length: -1, body: io.NopCloser(strings.NewReader(""))},
		{name: "reset content", method: http.MethodGet, status: http.StatusResetContent, length: -1, body: io.NopCloser(strings.NewReader(""))},
		{name: "not modified", method: http.MethodGet, status: http.StatusNotModified, length: -1, body: io.NopCloser(strings.NewReader(""))},
		{name: "successful CONNECT", method: http.MethodConnect, status: http.StatusOK, length: -1, body: io.NopCloser(strings.NewReader(""))},
		{name: "failed CONNECT", method: http.MethodConnect, status: http.StatusBadGateway, length: -1, body: io.NopCloser(strings.NewReader("x")), want: true},
		{name: "zero length", method: http.MethodGet, status: http.StatusOK, length: 0, body: io.NopCloser(strings.NewReader(""))},
		{name: "NoBody", method: http.MethodGet, status: http.StatusOK, length: -1, body: http.NoBody},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "http://example.com/", nil)
			res := &http.Response{StatusCode: tc.status, ContentLength: tc.length, Body: tc.body}
			if got := responseHasContent(req, res); got != tc.want {
				t.Errorf("responseHasContent() = %v, want %v", got, tc.want)
			}
		})
	}
}
