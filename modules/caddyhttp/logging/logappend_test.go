package logging

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestLogAppendPlaceholderDefaults(t *testing.T) {
	for _, value := range []string{`{missing:-fallback}`, `{missing:-{number}}`, `{source:-fallback}`} {
		req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
		repl := caddy.NewReplacer()
		repl.Set("number", 42)
		repl.Set("source", "{env.SECRET}")
		ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
		ctx = context.WithValue(ctx, caddyhttp.VarsCtxKey, map[string]any{})
		ctx = context.WithValue(ctx, caddyhttp.ExtraLogFieldsCtxKey, new(caddyhttp.ExtraLogFields))
		h := LogAppend{Key: "value", Value: value}
		if err := h.addLogField(req.WithContext(ctx), nil); err != nil {
			t.Fatalf("%s: %v", value, err)
		}
	}
}

func TestLogAppendMalformedDefaultErrors(t *testing.T) {
	downstreamErr := errors.New("downstream failed")
	for _, early := range []bool{true, false} {
		for _, nextErr := range []error{nil, downstreamErr} {
			req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
			ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer())
			ctx = context.WithValue(ctx, caddyhttp.VarsCtxKey, map[string]any{})
			ctx = context.WithValue(ctx, caddyhttp.ExtraLogFieldsCtxKey, new(caddyhttp.ExtraLogFields))
			h := LogAppend{Key: "value", Value: `{missing:-unclosed`, Early: early}
			called := false
			err := h.ServeHTTP(httptest.NewRecorder(), req.WithContext(ctx), caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { called = true; return nextErr }))
			if err == nil {
				t.Fatal("expected malformed default error")
			}
			if early && called {
				t.Fatal("malformed early field should fail before next handler")
			}
			if !early && nextErr != nil && !errors.Is(err, nextErr) {
				t.Fatalf("lost downstream error: %v", err)
			}
		}
	}
}

func TestLogAppendResponseBodyDefaults(t *testing.T) {
	for _, body := range []string{"response", ""} {
		req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
		repl := caddy.NewReplacer()
		fallbackCalls := 0
		repl.Map(func(key string) (any, bool) {
			if key != "fallback" {
				return nil, false
			}
			fallbackCalls++
			return "fallback", true
		})
		ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
		ctx = context.WithValue(ctx, caddyhttp.VarsCtxKey, map[string]any{})
		ctx = context.WithValue(ctx, caddyhttp.ExtraLogFieldsCtxKey, new(caddyhttp.ExtraLogFields))
		h := LogAppend{Key: "value", Value: `{missing:-{http.response.body:-{fallback}}}`}
		rec := httptest.NewRecorder()
		err := h.ServeHTTP(rec, req.WithContext(ctx), caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
			_, err := w.Write([]byte(body))
			return err
		}))
		if err != nil {
			t.Fatal(err)
		}
		if rec.Body.String() != body {
			t.Fatalf("response changed: %q", rec.Body.String())
		}
		wantCalls := 0
		if body == "" {
			wantCalls = 1
		}
		if fallbackCalls != wantCalls {
			t.Fatalf("body %q: fallback called %d times, want %d", body, fallbackCalls, wantCalls)
		}
	}
}
