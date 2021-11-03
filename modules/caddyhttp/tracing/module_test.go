package tracing

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestOpenTelemetry_UnmarshalCaddyfile(t *testing.T) {
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
	span_name my-span
}`),
			wantErr: false,
		},
		{
			name:     "Only span name in the config",
			spanName: "my-span",
			d: caddyfile.NewTestDispenser(`
tracing {
	span_name my-span
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

func TestOpenTelemetry_UnmarshalCaddyfile_Error(t *testing.T) {
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
	span_name
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

func TestOpenTelemetry_Provision(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	if err := th.SetEnv(); err != nil {
		t.Errorf("Environment variable set error: %v", err)
	}

	defer func() {
		if err := th.UnsetEnv(); err != nil {
			t.Errorf("Environment variable unset error: %v", err)
		}
	}()

	ot := &Tracing{}

	if err := ot.Provision(ctx); err != nil {
		t.Errorf("Provision() error = %v", err)
	}
}

func TestOpenTelemetry_Provision_WithoutEnvironmentVariables(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	ot := &Tracing{}

	if err := ot.Provision(ctx); err != nil {
		t.Errorf("Provision() error should be nil")
	}
}

func TestOpenTelemetry_ServeHTTP_Propagation_Without_Initial_Headers(t *testing.T) {
	if err := th.SetEnv(); err != nil {
		t.Errorf("Environment variable set error: %v", err)
	}

	defer func() {
		if err := th.UnsetEnv(); err != nil {
			t.Errorf("Environment variable unset error: %v", err)
		}
	}()

	ot := &Tracing{
		SpanName: "mySpan",
	}

	req := httptest.NewRequest("GET", "https://example.com/foo", nil)
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

func TestOpenTelemetry_ServeHTTP_Propagation_With_Initial_Headers(t *testing.T) {
	if err := th.SetEnv(); err != nil {
		t.Errorf("Environment variable set error: %v", err)
	}

	defer func() {
		if err := th.UnsetEnv(); err != nil {
			t.Errorf("Environment variable unset error: %v", err)
		}
	}()

	ot := &Tracing{
		SpanName: "mySpan",
	}

	req := httptest.NewRequest("GET", "https://example.com/foo", nil)
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

type testHelper struct {
	SetEnv   func() error
	UnsetEnv func() error
}

var th = testHelper{
	SetEnv: func() error {
		if err := os.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc"); err != nil {
			return err
		}

		if err := os.Setenv("OTEL_PROPAGATORS", "tracecontext,baggage"); err != nil {
			return err
		}

		return nil
	},
	UnsetEnv: func() error {
		if err := os.Unsetenv("OTEL_EXPORTER_OTLP_PROTOCOL"); err != nil {
			return err
		}

		if err := os.Unsetenv("OTEL_PROPAGATORS"); err != nil {
			return err
		}

		return nil
	},
}
