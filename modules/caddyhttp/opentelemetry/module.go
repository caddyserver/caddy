package opentelemetry

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Tracing{})
	httpcaddyfile.RegisterHandlerDirective("tracing", parseCaddyfile)
}

// OpenTelemetry implements an HTTP handler that adds support for the opentelemetry tracing.
// It is responsible for the injection and propagation of the tracing contexts.
// OpenTelemetry module can be configured via environment variables https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/sdk-environment-variables.md. Some values can be overwritten with values from the configuration file.
type OpenTelemetry struct {
	// SpanName is a span name. It SHOULD follow the naming guideline https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/trace/api.md#span
	SpanName string `json:"span"`

	// otel implements opentelemetry related logic.
	otel openTelemetryWrapper

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (OpenTelemetry) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.opentelemetry",
		New: func() caddy.Module { return new(OpenTelemetry) },
	}
}

// Provision implements caddy.Provisioner.
func (ot *OpenTelemetry) Provision(ctx caddy.Context) error {
	ot.logger = ctx.Logger(ot)

	var err error
	ot.otel, err = newOpenTelemetryWrapper(ctx, ot.SpanName)

	return err
}

// Cleanup implements caddy.CleanerUpper and closes any idle connections. It calls Shutdown method for a trace provider https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/trace/sdk.md#shutdown.
func (ot *OpenTelemetry) Cleanup() error {
	if err := ot.otel.cleanup(ot.logger); err != nil {
		return fmt.Errorf("tracerProvider shutdown: %w", err)
	}
	return nil
}

// Validate implements caddy.Validator.
func (ot *OpenTelemetry) Validate() error {
	if ot.otel.tracer == nil {
		return errors.New("openTelemetry tracer is nil")
	}

	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (ot *OpenTelemetry) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	return ot.otel.ServeHTTP(w, r, next)
}

// UnmarshalCaddyfile sets up the module from Caddyfile tokens.
func (ot *OpenTelemetry) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	setParameter := func(d *caddyfile.Dispenser, val *string) error {
		if d.NextArg() {
			*val = d.Val()
		} else {
			return d.ArgErr()
		}
		if d.NextArg() {
			return d.ArgErr()
		}
		return nil
	}

	// paramsMap is a mapping between "string" parameter from the Caddyfile and its destination within the module
	paramsMap := map[string]*string{
		"span_name": &ot.SpanName,
	}

	for d.Next() {
		args := d.RemainingArgs()
		if len(args) > 0 {
			return d.ArgErr()
		}

		for d.NextBlock(0) {
			if dst, ok := paramsMap[d.Val()]; ok {
				if err := setParameter(d, dst); err != nil {
					return err
				}
			} else {
				return d.ArgErr()
			}
		}
	}
	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m OpenTelemetry
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return &m, err
}

// Interface guards
var (
	_ caddy.Provisioner           = (*OpenTelemetry)(nil)
	_ caddy.Validator             = (*OpenTelemetry)(nil)
	_ caddyhttp.MiddlewareHandler = (*OpenTelemetry)(nil)
	_ caddyfile.Unmarshaler       = (*OpenTelemetry)(nil)
)
