package tracing

import (
	"context"
	"fmt"
	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.7.0"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"net/http"
)

const (
	webEngineName   = "Caddy"
	defaultSpanName = "handler"
	tracerName      = "github.com/caddyserver/caddy/v2/modules/caddyhttp/tracing"
)

// openTelemetryWrapper is responsible for the tracing injection, extraction and propagation.
type openTelemetryWrapper struct {
	tracer      trace.Tracer
	propagators propagation.TextMapPropagator

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

	// create a tracer
	ot.tracer = globalTracerProvider.getTracerProvider(
		sdktrace.WithBatcher(traceExporter),
		sdktrace.WithResource(res),
	).Tracer(tracerName)

	return ot, nil
}

// ServeHTTP extract current tracing context or create a new one, then method propagates it to the wrapped next handler.
func (ot *openTelemetryWrapper) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	opts := []trace.SpanStartOption{
		trace.WithAttributes(semconv.NetAttributesFromHTTPRequest("tcp", r)...),
		trace.WithAttributes(semconv.EndUserAttributesFromHTTPRequest(r)...),
		trace.WithAttributes(semconv.HTTPServerAttributesFromHTTPRequest("", "", r)...),
	}

	ctx := ot.propagators.Extract(r.Context(), propagation.HeaderCarrier(r.Header))

	// It will be default span kind as for now. Proper span kind (Span.Kind.LOAD_BALANCER (PROXY/SIDECAR)) is being discussed here https://github.com/open-telemetry/opentelemetry-specification/issues/51.
	ctx, span := ot.tracer.Start(ctx, ot.spanName, opts...)
	defer span.End()

	ot.propagators.Inject(ctx, propagation.HeaderCarrier(r.Header))

	err := next.ServeHTTP(w, r)
	if err != nil {
		span.RecordError(err)
		return err
	}

	return nil
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
