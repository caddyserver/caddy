package tracing

import (
	"context"
	"os"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

func TestOpenTelemetry_newOpenTelemetryWrapper(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	var otw openTelemetryWrapper
	var err error

	if otw, err = newOpenTelemetryWrapper(ctx,
		"",
	); err != nil {
		t.Errorf("newOpenTelemetryWrapper() error = %v", err)
		t.FailNow()
	}

	if otw.tracer == nil {
		t.Errorf("Tracer should not be empty")
	}

	if otw.propagators == nil {
		t.Errorf("Propagators should not be empty")
	}
}

func Test_openTelemetryWrapper_newResource_WithServiceName(t *testing.T) {
	err := os.Setenv("OTEL_SERVICE_NAME", "MyService")
	defer os.Unsetenv("OTEL_SERVICE_NAME")

	res, err := (&openTelemetryWrapper{}).newResource("TestEngine", "Version 1")

	if err != nil {
		t.Errorf("can not create resource: %v", err)
	}

	const expectedAttributesNumber = 6
	if len(res.Attributes()) != expectedAttributesNumber {
		t.Errorf("resource should have %d attributes, has : %v", expectedAttributesNumber, len(res.Attributes()))
	}

	attributesMap := make(map[string]string)
	for i := 0; i < expectedAttributesNumber; i++ {
		attributesMap[string(res.Attributes()[i].Key)] = res.Attributes()[i].Value.AsString()
	}

	for k, v := range map[string]string{
		"telemetry.sdk.language": "go",
		"telemetry.sdk.name":     "tracing",
		"webengine.version":      "Version 1",
		"webengine.name":         "TestEngine",
		"service.name":           "MyService",
	} {
		if attributesMap[k] != v {
			t.Errorf("attribute %v is %v, expeted %v", k, attributesMap[k], v)
		}
	}
}
