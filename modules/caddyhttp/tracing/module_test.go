package tracing

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestTracing_UnmarshalCaddyfile(t *testing.T) {
	tests := []struct {
		name           string
		spanName       string
		spanAttributes map[string]string
		d              *caddyfile.Dispenser
		wantErr        bool
	}{
		{
			name:     "Full config",
			spanName: "my-span",
			spanAttributes: map[string]string{
				"attr1": "value1",
				"attr2": "value2",
			},
			d: caddyfile.NewTestDispenser(`
tracing {
	span my-span
	span_attributes {
		attr1 value1
		attr2 value2
	}
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
		{
			name: "Only span attributes",
			spanAttributes: map[string]string{
				"service.name":    "my-service",
				"service.version": "1.0.0",
			},
			d: caddyfile.NewTestDispenser(`
tracing {
	span_attributes {
		service.name my-service
		service.version 1.0.0
	}
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

			if len(tt.spanAttributes) > 0 {
				if ot.SpanAttributes == nil {
					t.Errorf("UnmarshalCaddyfile() SpanAttributes is nil, expected %v", tt.spanAttributes)
				} else {
					for key, expectedValue := range tt.spanAttributes {
						if actualValue, exists := ot.SpanAttributes[key]; !exists {
							t.Errorf("UnmarshalCaddyfile() SpanAttributes missing key %v", key)
						} else if actualValue != expectedValue {
							t.Errorf("UnmarshalCaddyfile() SpanAttributes[%v] = %v, want %v", key, actualValue, expectedValue)
						}
					}
				}
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
		{
			name: "Span attributes missing value",
			d: caddyfile.NewTestDispenser(`
tracing {
	span_attributes {
		key
	}
}`),
			wantErr: true,
		},
		{
			name: "Span attributes too many arguments",
			d: caddyfile.NewTestDispenser(`
tracing {
	span_attributes {
		key value extra
	}
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

func TestTracing_JSON_Configuration(t *testing.T) {
	// Test that our struct correctly marshals to and from JSON
	original := &Tracing{
		SpanName: "test-span",
		SpanAttributes: map[string]string{
			"service.name":    "test-service",
			"service.version": "1.0.0",
			"env":             "test",
		},
	}

	jsonData, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Failed to marshal to JSON: %v", err)
	}

	var unmarshaled Tracing
	if err := json.Unmarshal(jsonData, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal from JSON: %v", err)
	}

	if unmarshaled.SpanName != original.SpanName {
		t.Errorf("Expected SpanName %s, got %s", original.SpanName, unmarshaled.SpanName)
	}

	if len(unmarshaled.SpanAttributes) != len(original.SpanAttributes) {
		t.Errorf("Expected %d span attributes, got %d", len(original.SpanAttributes), len(unmarshaled.SpanAttributes))
	}

	for key, expectedValue := range original.SpanAttributes {
		if actualValue, exists := unmarshaled.SpanAttributes[key]; !exists {
			t.Errorf("Expected span attribute %s to exist", key)
		} else if actualValue != expectedValue {
			t.Errorf("Expected span attribute %s = %s, got %s", key, expectedValue, actualValue)
		}
	}

	t.Logf("JSON representation: %s", string(jsonData))
}

func TestTracing_OpenTelemetry_Span_Attributes(t *testing.T) {
	// Create an in-memory span recorder to capture actual span data
	spanRecorder := tracetest.NewSpanRecorder()
	provider := trace.NewTracerProvider(
		trace.WithSpanProcessor(spanRecorder),
	)

	// Create our tracing module with span attributes that include placeholders
	ot := &Tracing{
		SpanName: "test-span",
		SpanAttributes: map[string]string{
			"static":               "test-service",
			"request-placeholder":  "{http.request.method}",
			"response-placeholder": "{http.response.header.X-Some-Header}",
			"mixed":                "prefix-{http.request.method}-{http.response.header.X-Some-Header}",
		},
	}

	// Create a specific request to test against
	req, _ := http.NewRequest("POST", "https://api.example.com/v1/users?id=123", nil)
	req.Host = "api.example.com"

	w := httptest.NewRecorder()

	// Set up the replacer
	repl := caddy.NewReplacer()
	ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
	ctx = context.WithValue(ctx, caddyhttp.VarsCtxKey, make(map[string]any))
	req = req.WithContext(ctx)

	// Set up request placeholders
	repl.Set("http.request.method", req.Method)
	repl.Set("http.request.uri", req.URL.RequestURI())

	// Handler to generate the response
	var handler caddyhttp.HandlerFunc = func(writer http.ResponseWriter, request *http.Request) error {
		writer.Header().Set("X-Some-Header", "some-value")
		writer.WriteHeader(200)

		// Make response headers available to replacer
		repl.Set("http.response.header.X-Some-Header", writer.Header().Get("X-Some-Header"))

		return nil
	}

	// Set up Caddy context
	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	// Override the global tracer provider with our test provider
	// This is a bit hacky but necessary to capture the actual spans
	originalProvider := globalTracerProvider
	globalTracerProvider = &tracerProvider{
		tracerProvider:         provider,
		tracerProvidersCounter: 1, // Simulate one user
	}
	defer func() {
		globalTracerProvider = originalProvider
	}()

	// Provision the tracing module
	if err := ot.Provision(caddyCtx); err != nil {
		t.Errorf("Provision error: %v", err)
		t.FailNow()
	}

	// Execute the request
	if err := ot.ServeHTTP(w, req, handler); err != nil {
		t.Errorf("ServeHTTP error: %v", err)
	}

	// Get the recorded spans
	spans := spanRecorder.Ended()
	if len(spans) == 0 {
		t.Fatal("Expected at least one span to be recorded")
	}

	// Find our span (should be the one with our test span name)
	var testSpan trace.ReadOnlySpan
	for _, span := range spans {
		if span.Name() == "test-span" {
			testSpan = span
			break
		}
	}

	if testSpan == nil {
		t.Fatal("Could not find test span in recorded spans")
	}

	// Verify that the span attributes were set correctly with placeholder replacement
	expectedAttributes := map[string]string{
		"static":               "test-service",
		"request-placeholder":  "POST",
		"response-placeholder": "some-value",
		"mixed":                "prefix-POST-some-value",
	}

	actualAttributes := make(map[string]string)
	for _, attr := range testSpan.Attributes() {
		actualAttributes[string(attr.Key)] = attr.Value.AsString()
	}

	for key, expectedValue := range expectedAttributes {
		if actualValue, exists := actualAttributes[key]; !exists {
			t.Errorf("Expected span attribute %s to be set", key)
		} else if actualValue != expectedValue {
			t.Errorf("Expected span attribute %s = %s, got %s", key, expectedValue, actualValue)
		}
	}

	t.Logf("Recorded span attributes: %+v", actualAttributes)
}

func createRequestWithContext(method string, url string) *http.Request {
	r, _ := http.NewRequest(method, url, nil)
	repl := caddy.NewReplacer()
	ctx := context.WithValue(r.Context(), caddy.ReplacerCtxKey, repl)
	r = r.WithContext(ctx)
	return r
}
