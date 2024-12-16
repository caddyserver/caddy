package tracing

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestTracing_UnmarshalCaddyfile(t *testing.T) {
	tests := []struct {
		name     string
		spanName string
		d        *caddyfile.Dispenser
		wantErr  bool
	}{
		{
			name:     "Full config",
			spanName: "my-span",
			d: caddyfile.NewTestDispenser(`
tracing {
	span my-span
}`),
			wantErr: false,
		},
		{
			name:     "Only span name in the config",
			spanName: "my-span",
			d: caddyfile.NewTestDispenser(`
tracing {
	span my-span
}`),
			wantErr: false,
		},
		{
			name: "Empty config",
			d: caddyfile.NewTestDispenser(`
tracing {
}`),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ot := &Tracing{}
			if err := ot.UnmarshalCaddyfile(tt.d); (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalCaddyfile() error = %v, wantErrType %v", err, tt.wantErr)
			}

			if ot.SpanName != tt.spanName {
				t.Errorf("UnmarshalCaddyfile() SpanName = %v, want SpanName %v", ot.SpanName, tt.spanName)
			}
		})
	}
}

func TestTracing_UnmarshalCaddyfile_Error(t *testing.T) {
	tests := []struct {
		name    string
		d       *caddyfile.Dispenser
		wantErr bool
	}{
		{
			name: "Unknown parameter",
			d: caddyfile.NewTestDispenser(`
		tracing {
			foo bar
		}`),
			wantErr: true,
		},
		{
			name: "Missed argument",
			d: caddyfile.NewTestDispenser(`
tracing {
	span
}`),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ot := &Tracing{}
			if err := ot.UnmarshalCaddyfile(tt.d); (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalCaddyfile() error = %v, wantErrType %v", err, tt.wantErr)
			}
		})
	}
}

func TestTracing_ServeHTTP_Propagation_Without_Initial_Headers(t *testing.T) {
	ot := &Tracing{
		SpanName: "mySpan",
	}

	req := createRequestWithContext("GET", "https://example.com/foo")
	w := httptest.NewRecorder()

	var handler caddyhttp.HandlerFunc = func(writer http.ResponseWriter, request *http.Request) error {
		traceparent := request.Header.Get("Traceparent")
		if traceparent == "" || strings.HasPrefix(traceparent, "00-00000000000000000000000000000000-0000000000000000") {
			t.Errorf("Invalid traceparent: %v", traceparent)
		}

		return nil
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	if err := ot.Provision(ctx); err != nil {
		t.Errorf("Provision error: %v", err)
		t.FailNow()
	}

	if err := ot.ServeHTTP(w, req, handler); err != nil {
		t.Errorf("ServeHTTP error: %v", err)
	}
}

func TestTracing_ServeHTTP_Propagation_With_Initial_Headers(t *testing.T) {
	ot := &Tracing{
		SpanName: "mySpan",
	}

	req := createRequestWithContext("GET", "https://example.com/foo")
	req.Header.Set("traceparent", "00-11111111111111111111111111111111-1111111111111111-01")
	w := httptest.NewRecorder()

	var handler caddyhttp.HandlerFunc = func(writer http.ResponseWriter, request *http.Request) error {
		traceparent := request.Header.Get("Traceparent")
		if !strings.HasPrefix(traceparent, "00-11111111111111111111111111111111") {
			t.Errorf("Invalid traceparent: %v", traceparent)
		}

		return nil
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	if err := ot.Provision(ctx); err != nil {
		t.Errorf("Provision error: %v", err)
		t.FailNow()
	}

	if err := ot.ServeHTTP(w, req, handler); err != nil {
		t.Errorf("ServeHTTP error: %v", err)
	}
}

func TestTracing_ServeHTTP_Next_Error(t *testing.T) {
	ot := &Tracing{
		SpanName: "mySpan",
	}

	req := createRequestWithContext("GET", "https://example.com/foo")
	w := httptest.NewRecorder()

	expectErr := errors.New("test error")

	var handler caddyhttp.HandlerFunc = func(writer http.ResponseWriter, request *http.Request) error {
		return expectErr
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	if err := ot.Provision(ctx); err != nil {
		t.Errorf("Provision error: %v", err)
		t.FailNow()
	}

	if err := ot.ServeHTTP(w, req, handler); err == nil || !errors.Is(err, expectErr) {
		t.Errorf("expected error, got: %v", err)
	}
}

func createRequestWithContext(method string, url string) *http.Request {
	r, _ := http.NewRequest(method, url, nil)
	repl := caddy.NewReplacer()
	ctx := context.WithValue(r.Context(), caddy.ReplacerCtxKey, repl)
	r = r.WithContext(ctx)
	return r
}
