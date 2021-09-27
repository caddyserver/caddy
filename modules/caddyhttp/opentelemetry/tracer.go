package opentelemetry

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"go.opentelemetry.io/otel/attribute"

	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"google.golang.org/grpc/credentials"
)

const (
	envOtelPropagators = "OTEL_PROPAGATORS"

	envOtelExporterOtlpProtocol       = "OTEL_EXPORTER_OTLP_PROTOCOL"
	envOtelExporterOtlpTracesProtocol = "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL"

	envOtelExporterOtlpCertificate       = "OTEL_EXPORTER_OTLP_CERTIFICATE"
	envOtelExporterOtlpTracesCertificate = "OTEL_EXPORTER_OTLP_TRACES_CERTIFICATE"

	envOtelExporterOtlpInsecure     = "OTEL_EXPORTER_OTLP_INSECURE"
	envOtelExporterOtlpSpanInsecure = "OTEL_EXPORTER_OTLP_SPAN_INSECURE"

	webEngineName   = "Caddy"
	defaultSpanName = "handler"
)

var (
	ErrUnspecifiedTracesProtocol  = errors.New("unspecified opentelemetry traces protocol")
	ErrUnsupportedTracesProtocol = errors.New("unsupported opentelemetry traces protocol")
	ErrUnspecifiedPropagators     = errors.New("unspecified opentelemtry propagators")
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

	res, err := ot.newResource(ctx, webEngineName, caddycmd.CaddyVersion())
	if err != nil {
		return ot, fmt.Errorf("creating resource error: %w", err)
	}

	//
	traceExporter, err := ot.getTracerExporter(ctx)
	if err != nil {
		return ot, fmt.Errorf("creating trace exporter error: %w", err)
	}

	// handle propagators related configuration, because it is not supported by opentelemetry lib yet.
	// Please check status of https://github.com/open-telemetry/opentelemetry-go/issues/1698.
	propagators := os.Getenv(envOtelPropagators)
	if propagators == "" {
		return ot, ErrUnspecifiedPropagators
	}

	ot.propagators = ot.getPropagators(propagators)

	// create a tracer
	ot.tracer = globalTracerProvider.getTracerProvider(
		sdktrace.WithBatcher(traceExporter),
		sdktrace.WithResource(res),
	).Tracer("github.com/caddyserver/caddy/v2/modules/caddyhttp/opentelemetry")

	return ot, nil
}

// ServeHTTP extract current tracing context or create a new one, then method propagates it to the wrapped next handler.
func (ot *openTelemetryWrapper) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {

	commonLabels := []attribute.KeyValue{
		attribute.String("http.method", r.Method),
		attribute.String("http.scheme", r.URL.Scheme),
		attribute.String("http.host", r.Host),
		attribute.String("http.user_agent", r.UserAgent()),
	}

	// It will be default span kind as for now. Proper span kind (Span.Kind.LOAD_BALANCER (PROXY/SIDECAR)) is being discussed here https://github.com/open-telemetry/opentelemetry-specification/issues/51.
	ctx, span := ot.tracer.Start(
		ot.propagators.Extract(r.Context(), propagation.HeaderCarrier(r.Header)),
		ot.spanName,
		trace.WithAttributes(commonLabels...),
	)
	defer span.End()

	ot.propagators.Inject(ctx, propagation.HeaderCarrier(r.Header))

	return next.ServeHTTP(w, r)
}

// cleanup flush all remaining data and shutdown a tracerProvider
func (ot *openTelemetryWrapper) cleanup(logger *zap.Logger) error {
	return globalTracerProvider.cleanupTracerProvider(logger)
}

// newResource creates a resource that describe current handler instance and merge it with a default attributes value.
func (ot *openTelemetryWrapper) newResource(
	ctx context.Context,
	webEngineName,
	webEngineVersion string,
) (*resource.Resource, error) {
	option := resource.WithAttributes(
		semconv.WebEngineNameKey.String(webEngineName),
		semconv.WebEngineVersionKey.String(webEngineVersion),
	)

	caddyResource, err := resource.New(ctx,
		option,
		resource.WithFromEnv(),
	)

	if err != nil {
		return nil, err
	}

	return resource.Merge(resource.Default(), caddyResource)
}

// getTracerExporter returns protocol specific exporter or error if the protocol is not supported by current module implementation.
//
// If opentelemetry is not configured with "insecure" parameter and certificate related headers missed,
// then default TLS with default `tls.Config` config will be used.
func (ot *openTelemetryWrapper) getTracerExporter(ctx context.Context) (*otlptrace.Exporter, error) {
	exporterTracesProtocol := ot.getTracesProtocolFromEnv()

	switch exporterTracesProtocol {
	case "grpc":
		var opts []otlptracegrpc.Option
		if ot.getInsecureFromEnv() {
			opts = append(opts, otlptracegrpc.WithInsecure())
		} else {
			if !ot.isCertificateHeaderSet() {
				var tlsConf tls.Config
				transportCredentials := credentials.NewTLS(&tlsConf)
				opts = append(opts, otlptracegrpc.WithTLSCredentials(transportCredentials))
			}
		}

		return otlptracegrpc.New(ctx, opts...)
	case "":
		return nil, ErrUnspecifiedTracesProtocol
	default:
		return nil, fmt.Errorf("%w: tracesProtocol %s", ErrNonSupportedTracesProtocol, exporterTracesProtocol)
	}
}

// getTracesProtocolFromEnv returns opentelemetry exporter otlp protocol, if it is specified via environment variable or empty string if not.
func (ot *openTelemetryWrapper) getTracesProtocolFromEnv() string {
	protocol := os.Getenv(envOtelExporterOtlpTracesProtocol)
	if protocol == "" {
		protocol = os.Getenv(envOtelExporterOtlpProtocol)
	}

	return protocol
}

// getInsecureFromEnv returns value of "insecure" option if it was specified by environment variable.
func (ot *openTelemetryWrapper) getInsecureFromEnv() bool {
	insecure := os.Getenv(envOtelExporterOtlpSpanInsecure)
	if insecure == "" {
		insecure = os.Getenv(envOtelExporterOtlpInsecure)
	}

	return strings.ToLower(insecure) == "true"
}

func (ot *openTelemetryWrapper) isCertificateHeaderSet() bool {
	return os.Getenv(envOtelExporterOtlpCertificate) != "" || os.Getenv(envOtelExporterOtlpTracesCertificate) != ""
}

// getPropagators deduplicate propagators, according to the specification https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/sdk-environment-variables.md#general-sdk-configuration.
// Parameter propagators is a "," separated string, ex: "baggage,tracecontext".
// Current implementation supports only "baggage" and "tracecontext" values.
func (ot *openTelemetryWrapper) getPropagators(propagators string) propagation.TextMapPropagator {
	// deduplicationMap filters duplicated propagator
	deduplicationMap := make(map[string]struct{})

	// store unique values
	var propagatorsList []propagation.TextMapPropagator

	for _, v := range strings.Split(propagators, ",") {
		propagatorName := strings.TrimSpace(v)
		if _, ok := deduplicationMap[propagatorName]; !ok {
			deduplicationMap[propagatorName] = struct{}{}
			switch propagatorName {
			case "baggage":
				propagatorsList = append(propagatorsList, propagation.Baggage{})
			case "tracecontext":
				propagatorsList = append(propagatorsList, propagation.TraceContext{})
			}
		}
	}

	return propagation.NewCompositeTextMapPropagator(propagatorsList...)
}
