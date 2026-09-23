package reverseproxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// 101 responses strip hop-by-hop headers (Alt-Svc, Keep-Alive, etc.) but preserve Upgrade and Connection
func TestFinalizeResponse_101_StripsHopByHopHeaders(t *testing.T) {
	h := &Handler{logger: caddy.Log()}

	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")

	vars := map[string]any{}
	ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, vars)
	req = req.WithContext(ctx)

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: http.Header{
			"Upgrade":              {"websocket"},
			"Connection":           {"Upgrade"},
			"Sec-Websocket-Accept": {"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="},
			"Alt-Svc":              {"h2=\"evil.com:443\"; ma=86400"},
			"Keep-Alive":           {"timeout=999"},
			"Proxy-Authenticate":   {"Basic realm=\"phish\""},
		},
		Body: fakeRWC{strings.NewReader("")},
	}

	repl := caddy.NewReplacer()
	rw := httptest.NewRecorder()

	err := h.finalizeResponse(rw, req, res, repl, fakeStart, caddy.Log())
	if err != nil {
		t.Logf("finalizeResponse returned error (expected, no real conn): %v", err)
	}

	if got := rw.Header().Get("Upgrade"); got != "websocket" {
		t.Errorf("Upgrade = %q, want %q", got, "websocket")
	}
	if got := rw.Header().Get("Connection"); got != "Upgrade" {
		t.Errorf("Connection = %q, want %q", got, "Upgrade")
	}
	for _, hdr := range []string{"Alt-Svc", "Keep-Alive", "Proxy-Authenticate"} {
		if got := rw.Header().Get(hdr); got != "" {
			t.Errorf("%s = %q, want empty (should be stripped)", hdr, got)
		}
	}
}

// Headers named in the upstream Connection value are stripped
func TestFinalizeResponse_101_StripsConnectionNamedHeaders(t *testing.T) {
	h := &Handler{logger: caddy.Log()}

	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")

	vars := map[string]any{}
	ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, vars)
	req = req.WithContext(ctx)

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: http.Header{
			"Upgrade":              {"websocket"},
			"Connection":           {"Upgrade, X-Custom-ID"},
			"Sec-Websocket-Accept": {"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="},
			"X-Custom-Id":          {"should-be-stripped"},
		},
		Body: fakeRWC{strings.NewReader("")},
	}

	repl := caddy.NewReplacer()
	rw := httptest.NewRecorder()

	err := h.finalizeResponse(rw, req, res, repl, fakeStart, caddy.Log())
	if err != nil {
		t.Logf("finalizeResponse returned error (no real connection): %v", err)
	}

	if got := rw.Header().Get("Upgrade"); got != "websocket" {
		t.Errorf("Upgrade = %q, want %q", got, "websocket")
	}
	if got := rw.Header().Get("X-Custom-Id"); got != "" {
		t.Errorf("X-Custom-Id = %q, want empty (named in Connection, should be stripped)", got)
	}
	if got := rw.Header().Get("Connection"); got != "Upgrade" {
		t.Errorf("Connection = %q, want %q", got, "Upgrade")
	}
}

// Normal 200 responses strip hop-by-hop headers
func TestFinalizeResponse_200_StillStripsHopByHop(t *testing.T) {
	h := &Handler{logger: caddy.Log()}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	vars := map[string]any{}
	ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, vars)
	req = req.WithContext(ctx)

	res := &http.Response{
		StatusCode: http.StatusOK,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: http.Header{
			"Content-Type": {"text/plain"},
			"Alt-Svc":      {"h2=\"evil.com:443\""},
			"Keep-Alive":   {"timeout=999"},
		},
		Body: io.NopCloser(strings.NewReader("ok")),
	}

	repl := caddy.NewReplacer()
	rw := httptest.NewRecorder()

	err := h.finalizeResponse(rw, req, res, repl, fakeStart, caddy.Log())
	if err != nil {
		t.Fatalf("finalizeResponse returned error: %v", err)
	}

	for _, hdr := range []string{"Alt-Svc", "Keep-Alive"} {
		if got := rw.Header().Get(hdr); got != "" {
			t.Errorf("%s = %q on 200 response, want empty (stripped)", hdr, got)
		}
	}
}

// Stripping still runs when the client didn't request an upgrade
func TestFinalizeResponse_101_NoUpgradeRequest(t *testing.T) {
	h := &Handler{logger: caddy.Log()}

	req := httptest.NewRequest(http.MethodGet, "/ws", nil)

	vars := map[string]any{}
	ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, vars)
	req = req.WithContext(ctx)

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: http.Header{
			"Upgrade":    {"websocket"},
			"Connection": {"Upgrade"},
			"Alt-Svc":    {"h2=\"evil.com:443\""},
		},
		Body: io.NopCloser(strings.NewReader("")),
	}

	repl := caddy.NewReplacer()
	rw := httptest.NewRecorder()

	err := h.finalizeResponse(rw, req, res, repl, fakeStart, caddy.Log())
	if err != nil {
		t.Fatalf("finalizeResponse returned error: %v", err)
	}

	if got := rw.Header().Get("Alt-Svc"); got != "" {
		t.Errorf("Alt-Svc = %q, want empty (stripped)", got)
	}
}

// fakeRWC lets handleUpgradeResponse proceed past the body type assertion in tests
type fakeRWC struct {
	io.Reader
}

func (f fakeRWC) Write(p []byte) (n int, err error) { return len(p), nil }
func (f fakeRWC) Close() error                      { return nil }

var fakeStart = time.Time{}
