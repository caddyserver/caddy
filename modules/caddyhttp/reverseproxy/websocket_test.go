package reverseproxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/headers"
)

func TestNormalizeWebsocketHeaders(t *testing.T) {
	tests := []struct {
		name  string
		input http.Header
		want  http.Header
	}{
		{
			name: "canonicalized headers are renamed to RFC 6455 form",
			input: http.Header{
				// Go's http.CanonicalHeaderKey lowercases the 'S' in WebSocket:
				// "Sec-WebSocket-Key" -> "Sec-Websocket-Key"
				"Sec-Websocket-Key":        {"dGhlIHNhbXBsZSBub25jZQ=="},
				"Sec-Websocket-Version":    {"13"},
				"Sec-Websocket-Protocol":   {"chat"},
				"Sec-Websocket-Extensions": {"permessage-deflate"},
			},
			want: http.Header{
				"Sec-WebSocket-Key":        {"dGhlIHNhbXBsZSBub25jZQ=="},
				"Sec-WebSocket-Version":    {"13"},
				"Sec-WebSocket-Protocol":   {"chat"},
				"Sec-WebSocket-Extensions": {"permessage-deflate"},
			},
		},
		{
			name: "already-correct headers are left unchanged",
			input: http.Header{
				"Sec-WebSocket-Key":     {"abc123"},
				"Sec-WebSocket-Version": {"13"},
			},
			want: http.Header{
				"Sec-WebSocket-Key":     {"abc123"},
				"Sec-WebSocket-Version": {"13"},
			},
		},
		{
			name:  "non-WebSocket headers are untouched",
			input: http.Header{"Content-Type": {"text/plain"}, "X-Foo": {"bar"}},
			want:  http.Header{"Content-Type": {"text/plain"}, "X-Foo": {"bar"}},
		},
		{
			name:  "empty header map is a no-op",
			input: http.Header{},
			want:  http.Header{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			normalizeWebsocketHeaders(tt.input)
			for k, wantV := range tt.want {
				gotV, ok := tt.input[k]
				if !ok {
					t.Errorf("missing header %q", k)
					continue
				}
				if len(gotV) != len(wantV) || gotV[0] != wantV[0] {
					t.Errorf("header %q: got %v, want %v", k, gotV, wantV)
				}
			}
			// Ensure no extra keys remain (old canonical forms must be deleted).
			for k := range tt.input {
				if _, ok := tt.want[k]; !ok {
					t.Errorf("unexpected header key left in map: %q", k)
				}
			}
		})
	}
}

// TestRebuildRequestHeadersPreservesWebsocketCasing is a regression test for
// https://github.com/caddyserver/caddy/issues/7784.
//
// proxyLoopIteration rebuilds r.Header with copyHeader when transport or header
// ops are configured. copyHeader uses http.Header.Add internally, which calls
// http.CanonicalHeaderKey and lowercases the 'S' in "WebSocket" to produce
// "Sec-Websocket-*". The rebuild path must restore the RFC 6455 casing before
// the request is forwarded.
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
						Add: http.Header{"X-Custom": {"v"}},
					},
				},
			},
		},
		{
			name: "transport-injected Host op only",
			handler: Handler{
				transportHeaderOps: &headers.HeaderOps{
					Set: http.Header{"Host": {"upstream.example.com"}},
				},
			},
		},
		{
			name: "transport and user ops together",
			handler: Handler{
				transportHeaderOps: &headers.HeaderOps{
					Set: http.Header{"Host": {"upstream.example.com"}},
				},
				Headers: &headers.Handler{
					Request: &headers.HeaderOps{
						Add: http.Header{"X-Custom": {"v"}},
					},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reqHeader := http.Header{}
			reqHeader["Sec-WebSocket-Key"] = []string{"dGhlIHNhbXBsZSBub25jZQ=="}
			reqHeader["Sec-WebSocket-Version"] = []string{"13"}
			reqHeader.Set("Connection", "Upgrade")
			reqHeader.Set("Upgrade", "websocket")

			req := httptest.NewRequest("GET", "http://example.com/", nil)
			ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer())
			req = req.WithContext(ctx)

			tc.handler.rebuildRequestHeaders(req, reqHeader, "upstream.example.com")

			for _, key := range []string{"Sec-WebSocket-Key", "Sec-WebSocket-Version"} {
				if _, ok := req.Header[key]; !ok {
					t.Errorf("%q missing after rebuild; header = %v", key, req.Header)
				}
				canonical := http.CanonicalHeaderKey(key)
				if canonical == key {
					continue
				}
				if _, ok := req.Header[canonical]; ok {
					t.Errorf("%q leaked after rebuild; header = %v", canonical, req.Header)
				}
			}
		})
	}
}

func TestRebuildRequestHeadersIsNoOpWithoutOps(t *testing.T) {
	h := Handler{}
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Original", "stays")
	otherHeader := http.Header{"Different": {"should-not-appear"}}

	h.rebuildRequestHeaders(req, otherHeader, "ignored")

	if got := req.Header.Get("Original"); got != "stays" {
		t.Errorf("header rebuilt despite no ops; Original = %q, want %q", got, "stays")
	}
	if got := req.Header.Get("Different"); got != "" {
		t.Errorf("reqHeader leaked despite no ops; Different = %q, want empty", got)
	}
}
