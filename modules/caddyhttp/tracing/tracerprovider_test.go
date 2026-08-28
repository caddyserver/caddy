package tracing

import (
	"errors"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.uber.org/zap"
)

func noOpts() ([]sdktrace.TracerProviderOption, error) {
	return nil, nil
}

func Test_tracersProvider_getTracerProvider(t *testing.T) {
	tp := tracerProvider{}

	_, _ = tp.getTracerProvider(noOpts)
	_, _ = tp.getTracerProvider(noOpts)

	if tp.tracerProvider == nil {
		t.Errorf("There should be tracer provider")
	}

	if tp.tracerProvidersCounter != 2 {
		t.Errorf("Tracer providers counter should equal to 2")
	}
}

func Test_tracersProvider_cleanupTracerProvider(t *testing.T) {
	tp := tracerProvider{}

	_, _ = tp.getTracerProvider(noOpts)
	_, _ = tp.getTracerProvider(noOpts)

	err := tp.cleanupTracerProvider(zap.NewNop())
	if err != nil {
		t.Errorf("There should be no error: %v", err)
	}

	if tp.tracerProvider == nil {
		t.Errorf("There should be tracer provider")
	}

	if tp.tracerProvidersCounter != 1 {
		t.Errorf("Tracer providers counter should equal to 1")
	}
}

// Test_tracersProvider_buildOptsOnlyOnCreate guards against a goroutine leak on
// config reload: buildOpts must be invoked only when a new provider is actually
// created, never on the reuse path. Some options (e.g. sdktrace.WithBatcher)
// eagerly start a BatchSpanProcessor goroutine when constructed, so calling
// buildOpts on every reload would leak one goroutine per reload.
func Test_tracersProvider_buildOptsOnlyOnCreate(t *testing.T) {
	tp := tracerProvider{}

	builds := 0
	build := func() ([]sdktrace.TracerProviderOption, error) {
		builds++
		return nil, nil
	}

	// First call creates the provider and must build options.
	_, _ = tp.getTracerProvider(build)
	// Subsequent calls reuse the existing provider and must NOT build options again.
	for i := 0; i < 5; i++ {
		_, _ = tp.getTracerProvider(build)
	}

	if builds != 1 {
		t.Errorf("buildOpts should be invoked exactly once (on create), got %d", builds)
	}
	if tp.tracerProvidersCounter != 6 {
		t.Errorf("Tracer providers counter should equal to 6, got %d", tp.tracerProvidersCounter)
	}
}

// Test_tracersProvider_buildOptsError verifies that an error from buildOpts is
// propagated and that no provider is created nor the counter incremented, so a
// failed build leaves the tracerProvider in its initial state.
func Test_tracersProvider_buildOptsError(t *testing.T) {
	tp := tracerProvider{}

	wantErr := errors.New("build failed")
	build := func() ([]sdktrace.TracerProviderOption, error) {
		return nil, wantErr
	}

	_, err := tp.getTracerProvider(build)
	if !errors.Is(err, wantErr) {
		t.Errorf("Expected error %v, got %v", wantErr, err)
	}

	if tp.tracerProvider != nil {
		t.Errorf("There should be no tracer provider when buildOpts fails")
	}

	if tp.tracerProvidersCounter != 0 {
		t.Errorf("Tracer providers counter should equal to 0, got %d", tp.tracerProvidersCounter)
	}
}
