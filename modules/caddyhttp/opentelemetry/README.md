# OpenTelemetry module

This module provides integration with OpenTelemetry tracing facilities. It is implemented
as a `caddyhttp.MiddlewareHandler` and can be chained into a list of other handlers.

When enabled, it propagates an existing tracing context or will init a new one otherwise.

It is based on `https://github.com/open-telemetry/opentelemetry-go`.

## Configuration

### Environment variables

It can be configured using the environment variables defined
by the [OpenTelemetry Environment Variable Specification](https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/sdk-environment-variables.md).

IMPORTANT: Please, consider the version
of [https://github.com/open-telemetry/opentelemetry-go](https://github.com/open-telemetry/opentelemetry-go). Some parts
of the specification may be not implemented yet.

If neither OTEL_EXPORTER_OTLP_INSECURE nor OTEL_EXPORTER_OTLP_SPAN_INSECURE is provided, then:

1. If OTEL_EXPORTER_OTLP_CERTIFICATE or OTEL_EXPORTER_OTLP_TRACES_CERTIFICATE are specified they will be used for TLS.
2. Else if both OTEL_EXPORTER_OTLP_CERTIFICATE and OTEL_EXPORTER_OTLP_TRACES_CERTIFICATE are not specified, then default
   TLS with the default `tls.Config` config will be used for an exporter.

For the exporter configuration details, please
see [spec](https://github.com/open-telemetry/opentelemetry-specification/blob/a4440931b522c7351b0485ff4899f786b4ff4459/specification/protocol/exporter.md)
.

Example:

```bash
export OTEL_EXPORTER_OTLP_HEADERS="myAuthHeader=myToken"
export OTEL_EXPORTER_OTLP_PROTOCOL=grpc
export OTEL_PROPAGATORS=tracecontext,baggage
export OTEL_EXPORTER_OTLP_SPAN_INSECURE=false
export OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=localhost:12345
```

### Caddy file configuration

Here is a **Caddyfile** example:

```
handle /myHandler {
	opentelemetry {
		span_name my-span
	}
	reverse_proxy 127.0.0.1:8081
}
```

Please check span
naming [guideline](https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/trace/api.md#span)
.