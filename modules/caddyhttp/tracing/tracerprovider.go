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

// getTracerProvider create or return an existing global TracerProvider.
//
// buildOpts is only invoked when a new provider must actually be created.
// This matters because some options (notably sdktrace.WithBatcher) eagerly
// start background goroutines when constructed. Building them unconditionally
// and then discarding them on the reuse path would leak a BatchSpanProcessor
// goroutine on every config reload.
func (t *tracerProvider) getTracerProvider(buildOpts func() ([]sdktrace.TracerProviderOption, error)) (*sdktrace.TracerProvider, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.tracerProvider == nil {
		opts, err := buildOpts()
		if err != nil {
			return nil, err
		}
		t.tracerProvider = sdktrace.NewTracerProvider(
			opts...,
		)
	}

	t.tracerProvidersCounter++

	return t.tracerProvider, nil
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
