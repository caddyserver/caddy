package reverseproxy

import (
	"net/http"
	"testing"
)

func TestNormalizeWebsocketHeaders(t *testing.T) {
	tests := []struct {
		name   string
		input  http.Header
		want   http.Header
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

// TestNormalizeWebsocketHeadersSurvivesCopyHeader is a regression test for
// https://github.com/caddyserver/caddy/issues/7784.
//
// proxyLoopIteration rebuilds r.Header with copyHeader when transport or header
// ops are configured. copyHeader uses http.Header.Add internally, which calls
// http.CanonicalHeaderKey and lowercases the 'S' in "WebSocket" to produce
// "Sec-Websocket-*". The fix calls normalizeWebsocketHeaders after the rebuild
// so the RFC 6455 casing is restored before the request is forwarded.
func TestNormalizeWebsocketHeadersSurvivesCopyHeader(t *testing.T) {
	// Simulate the state of r.Header after copyHeader re-canonicalizes it.
	rebuilt := make(http.Header)
	// http.Header.Add canonicalizes to "Sec-Websocket-Key" (lowercase 's').
	rebuilt.Add("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	rebuilt.Add("Sec-WebSocket-Version", "13")

	// At this point the map contains the lowercase form.
	if _, ok := rebuilt["Sec-Websocket-Key"]; !ok {
		t.Fatal("test setup: expected canonical (lowercase) key to be present after Add")
	}

	// The fix: call normalizeWebsocketHeaders after the rebuild.
	normalizeWebsocketHeaders(rebuilt)

	// RFC 6455 form must be present (direct map lookup — .Get() re-canonicalizes
	// to "Sec-Websocket-Key" and would miss the corrected key).
	if _, ok := rebuilt["Sec-WebSocket-Key"]; !ok {
		t.Error("Sec-WebSocket-Key missing after normalize; WebSocket upgrade will fail")
	}
	// Lowercase form must be gone.
	if _, ok := rebuilt["Sec-Websocket-Key"]; ok {
		t.Error("canonical (lowercase) Sec-Websocket-Key still present after normalize")
	}
}
