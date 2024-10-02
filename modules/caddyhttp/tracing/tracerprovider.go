package tracing

import (
	"context"
	"fmt"
	"sync"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// globalTracerProvider stores global tracer provider and is responsible for graceful shutdown when nobody is using it.
var globalTracerProvider = &tracerProvider{}

type tracerProvider struct {
	mu                     sync.Mutex
	tracerProvider         *sdktrace.TracerProvider
	tracerProvidersCounter int
}

// getTracerProvider create or return an existing global TracerProvider
func (t *tracerProvider) getTracerProvider(opts ...sdktrace.TracerProviderOption) *sdktrace.TracerProvider {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.tracerProvidersCounter++

	if t.tracerProvider == nil {
		t.tracerProvider = sdktrace.NewTracerProvider(
			opts...,
		)
	}

	return t.tracerProvider
}

// cleanupTracerProvider gracefully shutdown a TracerProvider
func (t *tracerProvider) cleanupTracerProvider(logger *zap.Logger) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.tracerProvidersCounter > 0 {
		t.tracerProvidersCounter--
	}

	if t.tracerProvidersCounter == 0 {
		if t.tracerProvider != nil {
			// tracerProvider.ForceFlush SHOULD be invoked according to https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/trace/sdk.md#forceflush
			if err := t.tracerProvider.ForceFlush(context.Background()); err != nil {
				if c := logger.Check(zapcore.ErrorLevel, "forcing flush"); c != nil {
					c.Write(zap.Error(err))
				}
			}

			// tracerProvider.Shutdown MUST be invoked according to https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/trace/sdk.md#shutdown
			if err := t.tracerProvider.Shutdown(context.Background()); err != nil {
				return fmt.Errorf("tracerProvider shutdown error: %w", err)
			}
		}

		t.tracerProvider = nil
	}

	return nil
}
