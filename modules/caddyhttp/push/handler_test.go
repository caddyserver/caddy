package push

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

type mockPusher struct {
	http.ResponseWriter
	pushed bool
}

func (m *mockPusher) Push(target string, opts *http.PushOptions) error {
	m.pushed = true
	return nil
}

func BenchmarkServeHTTP(b *testing.B) {
	logger := zap.NewNop()
	h := Handler{
		Resources: []Resource{
			{Target: "/style.css", Method: "GET"},
		},
		logger: logger,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest("GET", "/", nil)

		// Setup Replacer and Server in context as required by ServeHTTP
		repl := caddy.NewReplacer()
		ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
		ctx = context.WithValue(ctx, caddyhttp.ServerCtxKey, &caddyhttp.Server{})
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		// Wrap with a pusher
		pusher := &mockPusher{ResponseWriter: rr}

		_ = h.ServeHTTP(pusher, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			w.Header().Set("Link", "</script.js>; rel=preload")
			w.WriteHeader(http.StatusOK)
			return nil
		}))
	}
}
