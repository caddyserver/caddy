package reverseproxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/headers"
)

func TestAddForwardedHeadersNonIP(t *testing.T) {
	h := Handler{}

	// Simulate a request with a non-IP remote address (e.g. SCION, abstract socket, or hostname)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "my-weird-network:12345"

	// Mock the context variables required by Caddy.
	// We need to inject the variable map manually since we aren't running the full server.
	vars := map[string]any{
		caddyhttp.TrustedProxyVarKey: false,
	}
	ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, vars)
	req = req.WithContext(ctx)

	// Execute the unexported function
	err := h.addForwardedHeaders(req)

	// Expectation: No error should be returned for non-IP addresses.
	// The function should simply skip the trusted proxy check.
	if err != nil {
		t.Errorf("expected no error for non-IP address, got: %v", err)
	}
}

func TestAddForwardedHeaders_UnixSocketTrusted(t *testing.T) {
	h := Handler{}

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "@"
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 10.0.0.1")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "original.example.com")

	vars := map[string]any{
		caddyhttp.TrustedProxyVarKey: true,
		caddyhttp.ClientIPVarKey:     "1.2.3.4",
	}
	ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, vars)
	req = req.WithContext(ctx)

	err := h.addForwardedHeaders(req)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if got := req.Header.Get("X-Forwarded-For"); got != "1.2.3.4, 10.0.0.1" {
		t.Errorf("X-Forwarded-For = %q, want %q", got, "1.2.3.4, 10.0.0.1")
	}
	if got := req.Header.Get("X-Forwarded-Proto"); got != "https" {
		t.Errorf("X-Forwarded-Proto = %q, want %q", got, "https")
	}
	if got := req.Header.Get("X-Forwarded-Host"); got != "original.example.com" {
		t.Errorf("X-Forwarded-Host = %q, want %q", got, "original.example.com")
	}
}

func TestAddForwardedHeaders_UnixSocketUntrusted(t *testing.T) {
	h := Handler{}

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "@"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "spoofed.example.com")

	vars := map[string]any{
		caddyhttp.TrustedProxyVarKey: false,
		caddyhttp.ClientIPVarKey:     "",
	}
	ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, vars)
	req = req.WithContext(ctx)

	err := h.addForwardedHeaders(req)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if got := req.Header.Get("X-Forwarded-For"); got != "" {
		t.Errorf("X-Forwarded-For should be deleted, got %q", got)
	}
	if got := req.Header.Get("X-Forwarded-Proto"); got != "" {
		t.Errorf("X-Forwarded-Proto should be deleted, got %q", got)
	}
	if got := req.Header.Get("X-Forwarded-Host"); got != "" {
		t.Errorf("X-Forwarded-Host should be deleted, got %q", got)
	}
}

func TestAddForwardedHeaders_UnixSocketTrustedNoExistingHeaders(t *testing.T) {
	h := Handler{}

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "@"

	vars := map[string]any{
		caddyhttp.TrustedProxyVarKey: true,
		caddyhttp.ClientIPVarKey:     "5.6.7.8",
	}
	ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, vars)
	req = req.WithContext(ctx)

	err := h.addForwardedHeaders(req)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if got := req.Header.Get("X-Forwarded-For"); got != "" {
		t.Errorf("X-Forwarded-For should be empty when no prior XFF exists, got %q", got)
	}
	if got := req.Header.Get("X-Forwarded-Proto"); got != "http" {
		t.Errorf("X-Forwarded-Proto = %q, want %q", got, "http")
	}
	if got := req.Header.Get("X-Forwarded-Host"); got != "example.com" {
		t.Errorf("X-Forwarded-Host = %q, want %q", got, "example.com")
	}
}

// TestRebuildRequestHeadersPreservesWebsocketCasing is a regression test for
// https://github.com/caddyserver/caddy/issues/7784. The header-rebuild path in
// proxyLoopIteration runs whenever a request header op is configured, or
// whenever the HTTPS transport auto-injects its Host op. copyHeader uses
// http.Header.Add, which canonicalizes the keys (Sec-WebSocket-Key ->
// Sec-Websocket-Key). Upstreams that compare these header names
// case-sensitively reject the WebSocket handshake. rebuildRequestHeaders must
// re-normalize the casing after the rebuild.
func TestRebuildRequestHeadersPreservesWebsocketCasing(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler Handler
	}{
		{
			name: "user header_ops only",
			handler: Handler{
				Headers: &headers.Handler{
					Request: &headers.HeaderOps{
						Add: http.Header{"X-Custom": []string{"v"}},
					},
				},
			},
		},
		{
			name: "transport-injected Host op only (HTTPS upstream)",
			handler: Handler{
				transportHeaderOps: &headers.HeaderOps{
					Set: http.Header{"Host": []string{"upstream.example.com"}},
				},
			},
		},
		{
			name: "transport and user ops together",
			handler: Handler{
				transportHeaderOps: &headers.HeaderOps{
					Set: http.Header{"Host": []string{"upstream.example.com"}},
				},
				Headers: &headers.Handler{
					Request: &headers.HeaderOps{
						Add: http.Header{"X-Custom": []string{"v"}},
					},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reqHeader := http.Header{}
			reqHeader["Sec-WebSocket-Key"] = []string{"dGhlIHNhbXBsZSBub25jZQ=="}
			reqHeader["Sec-WebSocket-Version"] = []string{"13"}
			reqHeader.Set("Upgrade", "websocket")
			reqHeader.Set("Connection", "Upgrade")

			req := httptest.NewRequest("GET", "http://example.com/", nil)
			// HeaderOps.ApplyToRequest reads the Replacer from the request context.
			ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer())
			req = req.WithContext(ctx)
			tc.handler.rebuildRequestHeaders(req, reqHeader, "upstream.example.com")

			for _, key := range []string{"Sec-WebSocket-Key", "Sec-WebSocket-Version"} {
				if _, ok := req.Header[key]; !ok {
					t.Errorf("%q (RFC 6455 casing) missing; header = %v", key, req.Header)
				}
				canonical := http.CanonicalHeaderKey(key)
				if canonical != key {
					if _, ok := req.Header[canonical]; ok {
						t.Errorf("%q (Go-canonical) leaked to upstream; header = %v", canonical, req.Header)
					}
				}
			}
		})
	}
}

// TestRebuildRequestHeadersIsNoOpWithoutOps verifies that when neither
// transport- nor user-configured header ops are present, the request header
// is left untouched (preserving the prior behavior of the inline rebuild
// block this helper replaced).
func TestRebuildRequestHeadersIsNoOpWithoutOps(t *testing.T) {
	h := Handler{}
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Original", "stays")
	otherHeader := http.Header{"Different": []string{"should-not-appear"}}

	h.rebuildRequestHeaders(req, otherHeader, "ignored")

	if got := req.Header.Get("Original"); got != "stays" {
		t.Errorf("header rebuilt despite no ops; Original = %q, want %q", got, "stays")
	}
	if got := req.Header.Get("Different"); got != "" {
		t.Errorf("reqHeader leaked despite no ops; Different = %q, want empty", got)
	}
}
