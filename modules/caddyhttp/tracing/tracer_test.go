package tracing

import (
	"context"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

func TestOpenTelemetryWrapper_newOpenTelemetryWrapper(t *testing.T) {
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

	if otw.propagators == nil {
		t.Errorf("Propagators should not be empty")
	}
}
