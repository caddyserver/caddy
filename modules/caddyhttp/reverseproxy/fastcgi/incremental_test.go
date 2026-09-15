package fastcgi

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/fcgi"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// fcgiBackend serves h over FastCGI and returns its address.
func fcgiBackend(t *testing.T, h http.Handler) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go fcgi.Serve(ln, h)

	return ln.Addr().String()
}

// fcgiRoundTrip sends req to a FastCGI backend at addr, the way the reverse
// proxy does once it has picked an upstream and decided not to buffer.
func fcgiRoundTrip(t *testing.T, addr string, req *http.Request) (*http.Response, error) {
	t.Helper()

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)

	transport := Transport{Root: "/", SplitPath: []string{".php"}}
	if err := transport.Provision(ctx); err != nil {
		t.Fatalf("provisioning transport: %v", err)
	}

	req.URL.Host = addr
	req = caddyhttp.PrepareRequest(req, caddy.NewReplacer(), nil, &caddyhttp.Server{})

	res, err := transport.RoundTrip(req)
	if res != nil {
		t.Cleanup(func() { res.Body.Close() })
	}

	return res, err
}

// A request whose length is known carries its own CONTENT_LENGTH, so fastcgi
// streams it without the request buffer it otherwise needs: refusing to
// forward it incrementally would deny a request that works fine unbuffered.
func TestIncrementalUnbufferedRequestWithKnownLength(t *testing.T) {
	var gotBody string
	var gotLength int64
	addr := fcgiBackend(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody, gotLength = string(b), r.ContentLength
	}))

	req := httptest.NewRequest(http.MethodPost, "http://example.com/index.php", strings.NewReader("hello"))
	req.Header.Set("Incremental", "?1")

	res, err := fcgiRoundTrip(t, addr, req)
	if err != nil {
		t.Fatalf("RoundTrip() error = %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", res.StatusCode)
	}
	if gotBody != "hello" {
		t.Errorf("upstream body = %q, want %q", gotBody, "hello")
	}
	if gotLength != 5 {
		t.Errorf("upstream CONTENT_LENGTH = %d, want 5", gotLength)
	}
}

// A request whose length is unknown, as a chunked request is, has no
// CONTENT_LENGTH to pass on, and the fastcgi client rejects it with 411 rather
// than let the upstream hang. Only the request buffer can supply that length,
// which is why incremental forwarding is refused instead in this case.
func TestIncrementalUnbufferedRequestWithUnknownLength(t *testing.T) {
	var reached bool
	addr := fcgiBackend(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))

	req := httptest.NewRequest(http.MethodPost, "http://example.com/index.php", io.NopCloser(strings.NewReader("hello")))
	req.Header.Set("Incremental", "?1")
	if req.ContentLength != -1 {
		t.Fatalf("ContentLength = %d, want -1", req.ContentLength)
	}

	_, err := fcgiRoundTrip(t, addr, req)

	var handlerErr caddyhttp.HandlerError
	if !errors.As(err, &handlerErr) {
		t.Fatalf("expected a caddyhttp.HandlerError, got %T: %v", err, err)
	}
	if handlerErr.StatusCode != http.StatusLengthRequired {
		t.Errorf("status = %d, want %d", handlerErr.StatusCode, http.StatusLengthRequired)
	}
	if reached {
		t.Error("request reached the upstream despite having no CONTENT_LENGTH")
	}
}

// Declaring that a length is required is what makes the reverse proxy refuse
// to forward a body of unknown length incrementally rather than send it on to
// the 411 above.
func TestRequiresContentLength(t *testing.T) {
	if !(Transport{}).RequiresContentLength() {
		t.Error("RequiresContentLength() = false, want true")
	}
}

// The request buffer fastcgi asks for by default is what supplies the
// CONTENT_LENGTH above, so these values matter beyond this package.
func TestDefaultBufferSizes(t *testing.T) {
	reqBuffers, respBuffers := Transport{}.DefaultBufferSizes()
	if reqBuffers != 4096 {
		t.Errorf("request buffers = %d, want 4096", reqBuffers)
	}
	if respBuffers != 0 {
		t.Errorf("response buffers = %d, want 0", respBuffers)
	}
}
