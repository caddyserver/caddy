package tracing

import (
	"testing"

	"go.uber.org/zap"
)

func Test_tracersProvider_getTracerProvider(t *testing.T) {
	tp := tracerProvider{}

	tp.getTracerProvider()
	tp.getTracerProvider()

	if tp.tracerProvider == nil {
		t.Errorf("There should be tracer provider")
	}

	if tp.tracerProvidersCounter != 2 {
		t.Errorf("Tracer providers counter should equal to 2")
	}
}

func Test_tracersProvider_cleanupTracerProvider(t *testing.T) {
	tp := tracerProvider{}

	tp.getTracerProvider()
	tp.getTracerProvider()

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
