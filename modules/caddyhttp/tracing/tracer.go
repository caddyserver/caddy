package tracing

import (
	"context"
	"fmt"
	"github.com/caddyserver/caddy/v2"
	"net/http"

	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.7.0"
	"go.uber.org/zap"
)

const (
	webEngineName                = "Caddy"
	defaultSpanName              = "handler"
	nextCallCtxKey  caddy.CtxKey = "nextCall"
)

// nextCall store the next handler, and the error value return on calling it (if any)
type nextCall struct {
	next caddyhttp.Handler
	err  error
}

// openTelemetryWrapper is responsible for the tracing injection, extraction and propagation.
type openTelemetryWrapper struct {
	propagators propagation.TextMapPropagator

	handler http.Handler

	spanName string
}

// newOpenTelemetryWrapper is responsible for the openTelemetryWrapper initialization using provided configuration.
func newOpenTelemetryWrapper(
	ctx context.Context,
	spanName string,
) (openTelemetryWrapper, error) {
	if spanName == "" {
		spanName = defaultSpanName
	}

	ot := openTelemetryWrapper{
		spanName: spanName,
	}

	res, err := ot.newResource(webEngineName, caddycmd.CaddyVersion())
	if err != nil {
		return ot, fmt.Errorf("creating resource error: %w", err)
	}

	traceExporter, err := otlptracegrpc.New(ctx)
	if err != nil {
		return ot, fmt.Errorf("creating trace exporter error: %w", err)
	}

	ot.propagators = propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{})

	tracerProvider := globalTracerProvider.getTracerProvider(
		sdktrace.WithBatcher(traceExporter),
		sdktrace.WithResource(res),
	)

	ot.handler = otelhttp.NewHandler(http.HandlerFunc(ot.serveHTTP), ot.spanName, otelhttp.WithTracerProvider(tracerProvider), otelhttp.WithPropagators(ot.propagators))
	return ot, nil
}

// serveHTTP injects a tracing context and call the next handler.
func (ot *openTelemetryWrapper) serveHTTP(w http.ResponseWriter, r *http.Request) {
	ot.propagators.Inject(r.Context(), propagation.HeaderCarrier(r.Header))
	next := r.Context().Value(nextCallCtxKey).(*nextCall)
	next.err = next.next.ServeHTTP(w, r)
}

// ServeHTTP propagates call to the by wrapped by `otelhttp` next handler.
func (ot *openTelemetryWrapper) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	n := &nextCall{
		next: next,
		err:  nil,
	}
	ot.handler.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), nextCallCtxKey, n)))

	return n.err
}

// cleanup flush all remaining data and shutdown a tracerProvider
func (ot *openTelemetryWrapper) cleanup(logger *zap.Logger) error {
	return globalTracerProvider.cleanupTracerProvider(logger)
}

// newResource creates a resource that describe current handler instance and merge it with a default attributes value.
func (ot *openTelemetryWrapper) newResource(
	webEngineName,
	webEngineVersion string,
) (*resource.Resource, error) {
	return resource.Merge(resource.Default(), resource.NewSchemaless(
		semconv.WebEngineNameKey.String(webEngineName),
		semconv.WebEngineVersionKey.String(webEngineVersion),
	))
}
