# Tracing module

This module provides integration with OpenTelemetry tracing facilities. It is implemented
as a `caddyhttp.MiddlewareHandler` and can be chained into a list of other handlers.

When enabled, it will propagate an existing trace context or initialize a new one.

It is based on `https://github.com/open-telemetry/opentelemetry-go`.

This module uses `gRPC` as an exporter protocol and  W3C `tracecontext` and `baggage` as propagators.

## Configuration

### Environment variables

This module can be configured using the environment variables defined
by the [OpenTelemetry Environment Variable Specification](https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/sdk-environment-variables.md).

For the exporter configuration details, please
see [spec](https://github.com/open-telemetry/opentelemetry-specification/blob/v1.7.0/specification/protocol/exporter.md)
.

Example:

```bash
export OTEL_EXPORTER_OTLP_HEADERS="myAuthHeader=myToken,anotherHeader=value"
export OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=https://my-otlp-endpoint:55680
```

### Caddyfile configuration

Here is a **Caddyfile** example:

```
handle /myHandler {
	tracing {
		span my-span
	}
	reverse_proxy 127.0.0.1:8081
}
```

Please see span naming [guidelines](https://github.com/open-telemetry/opentelemetry-specification/blob/v1.7.0/specification/trace/api.md).