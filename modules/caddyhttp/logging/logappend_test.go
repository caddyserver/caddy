package logging

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
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

func newLogAppendTestRequest(repl *caddy.Replacer) (*http.Request, *caddyhttp.ExtraLogFields) {
	r := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
	extra := new(caddyhttp.ExtraLogFields)
	ctx := context.WithValue(r.Context(), caddy.ReplacerCtxKey, repl)
	ctx = context.WithValue(ctx, caddyhttp.VarsCtxKey, map[string]any{})
	ctx = context.WithValue(ctx, caddyhttp.ExtraLogFieldsCtxKey, extra)
	return r.WithContext(ctx), extra
}

func TestLogAppendUnusedResponseDefaultStreams(t *testing.T) {
	for _, early := range []bool{false, true} {
		t.Run(fmt.Sprint(early), func(t *testing.T) {
			repl := caddy.NewReplacer()
			calls := 0
			primary := "known"
			repl.Map(func(key string) (any, bool) {
				if key == "primary" {
					calls++
					return primary, true
				}
				return nil, false
			})
			r, extra := newLogAppendTestRequest(repl)
			h := LogAppend{Key: "value", Value: `{primary:-{http.response.body}}`, Early: early}
			outer := httptest.NewRecorder()
			body := bytes.Repeat([]byte{'x'}, 1<<20)
			err := h.ServeHTTP(outer, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
				if _, err := w.Write(body); err != nil {
					return err
				}
				if err := http.NewResponseController(w).Flush(); err != nil {
					return err
				}
				if outer.Body.Len() != len(body) {
					t.Fatal("unused response-body fallback buffered the streaming response")
				}
				primary = "" // The selected value must remain frozen after streaming starts.
				return nil
			}))
			if err != nil || calls != 1 {
				t.Fatalf("got %v, primary resolved %d times", err, calls)
			}
			assertLogFieldCount(t, extra, 1)
		})
	}
}

func TestLogAppendSelectedResponseAndNoWriteDefaults(t *testing.T) {
	for _, write := range []bool{false, true} {
		for _, body := range []string{"", "response"} {
			t.Run(fmt.Sprintf("write=%v/body=%s", write, body), func(t *testing.T) {
				repl := caddy.NewReplacer()
				r, extra := newLogAppendTestRequest(repl)
				h := LogAppend{Key: "value", Value: `{missing:-prefix{http.response.body:-fallback}}`}
				outer := httptest.NewRecorder()
				err := h.ServeHTTP(outer, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
					if !write {
						return nil
					}
					_, err := w.Write([]byte(body))
					if outer.Body.Len() != 0 {
						t.Fatal("selected response body was not captured")
					}
					return err
				}))
				if err != nil {
					t.Fatal(err)
				}
				if write && outer.Body.String() != body {
					t.Fatal("capturing changed the response")
				}
				assertLogFieldCount(t, extra, 1)
				var buf *bytes.Buffer
				want := "prefixfallback"
				if write && body != "" {
					buf = bytes.NewBufferString(body)
					want = "prefix" + body
				}
				value, err := h.resolveLogValue(r, responseBodyProvider(buf, false))
				if err != nil || value != want {
					t.Fatalf("selected log value = %v, %v; want %q", value, err, want)
				}
			})
		}
	}
}

func TestLogAppendEarlyRequestBodyOnlyOnce(t *testing.T) {
	for _, value := range []string{`{http.request.body}`, `{missing:-{http.request.body}}`, `{http.request.body:-{http.response.body}}`} {
		t.Run(value, func(t *testing.T) {
			repl := caddy.NewReplacer()
			calls := 0
			repl.Map(func(key string) (any, bool) {
				if key == "http.request.body" {
					calls++
					return "request", true
				}
				return nil, false
			})
			r, extra := newLogAppendTestRequest(repl)
			h := LogAppend{Key: "value", Value: value}
			outer := httptest.NewRecorder()
			err := h.ServeHTTP(outer, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
				if calls != 1 {
					t.Fatal("selected request body was not captured early")
				}
				assertLogFieldCount(t, extra, 1)
				_, err := w.Write([]byte("response"))
				if outer.Body.String() != "response" {
					t.Fatal("unused response fallback was buffered")
				}
				return err
			}))
			if err != nil || calls != 1 {
				t.Fatalf("got %v, request body evaluated %d times", err, calls)
			}
			assertLogFieldCount(t, extra, 1)
		})
	}
}

func TestLogAppendBodyLimitAndDownstreamErrors(t *testing.T) {
	repl := caddy.NewReplacer()
	limit := caddyhttp.RequestBodyLimitError{Err: &http.MaxBytesError{Limit: 1}}
	repl.Set("http.request.body", limit)
	r, extra := newLogAppendTestRequest(repl)
	h := LogAppend{Key: "value", Value: `{missing:-{http.request.body}}`}
	called := false
	err := h.ServeHTTP(httptest.NewRecorder(), r, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		called = true
		return nil
	}))
	var handlerErr caddyhttp.HandlerError
	if called || !errors.As(err, &handlerErr) || handlerErr.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("lost early body-limit error: %v; downstream=%v", err, called)
	}
	assertLogFieldCount(t, extra, 0)

	downstreamErr := errors.New("downstream failed")
	for _, write := range []bool{false, true} {
		r, extra := newLogAppendTestRequest(caddy.NewReplacer())
		h := LogAppend{Key: "value", Value: `{missing:-{http.response.body:-fallback}}`}
		err := h.ServeHTTP(httptest.NewRecorder(), r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
			if write {
				_, _ = w.Write([]byte("response"))
			}
			return downstreamErr
		}))
		if !errors.Is(err, downstreamErr) {
			t.Fatalf("lost downstream error: %v", err)
		}
		assertLogFieldCount(t, extra, 1)
	}
}

func assertLogFieldCount(t *testing.T, extra *caddyhttp.ExtraLogFields, want int) {
	t.Helper()
	// ExtraLogFields deliberately exposes no field accessor; only inspect its
	// count to ensure middleware does not add a second field after early logging.
	if got := reflect.ValueOf(extra).Elem().FieldByName("fields").Len(); got != want {
		t.Fatalf("added %d log fields, want %d", got, want)
	}
}

// addLogField resolves and adds a field using the available response body.
func (h LogAppend) addLogField(r *http.Request, buf *bytes.Buffer) error {
	value, err := h.resolveLogValue(r, responseBodyProvider(buf, false))
	if err != nil {
		return err
	}
	return h.appendLogValue(r, value)
}

func TestLogAppendLateBodyLimitDoesNotCommitBufferedResponse(t *testing.T) {
	repl := caddy.NewReplacer()
	repl.Set("http.request.body", caddyhttp.RequestBodyLimitError{Err: &http.MaxBytesError{Limit: 1}})
	req, extra := newLogAppendTestRequest(repl)
	outer := &logAppendHeaderRecorder{ResponseRecorder: httptest.NewRecorder()}
	h := LogAppend{Key: "value", Value: `{http.response.body:-{http.request.body}}`}
	err := h.ServeHTTP(outer, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error { w.WriteHeader(http.StatusOK); return nil }))
	var handlerErr caddyhttp.HandlerError
	if !errors.As(err, &handlerErr) || handlerErr.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("lost late body-limit error: %v", err)
	}
	if outer.wroteHeader {
		t.Fatal("committed success response before returning body-limit error")
	}
	assertLogFieldCount(t, extra, 0)
}

type logAppendHeaderRecorder struct {
	*httptest.ResponseRecorder
	wroteHeader bool
}

func (w *logAppendHeaderRecorder) WriteHeader(status int) {
	w.wroteHeader = true
	w.ResponseRecorder.WriteHeader(status)
}
