package metrics

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestMetricsUnmarshalCaddyfile(t *testing.T) {
	m := &Metrics{}
	d := caddyfile.NewTestDispenser(`metrics bogus`)
	err := m.UnmarshalCaddyfile(d)
	if err == nil {
		t.Errorf("expected error")
	}

	m = &Metrics{}
	d = caddyfile.NewTestDispenser(`metrics`)
	err = m.UnmarshalCaddyfile(d)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if m.DisableOpenMetrics {
		t.Errorf("DisableOpenMetrics should've been false: %v", m.DisableOpenMetrics)
	}

	m = &Metrics{}
	d = caddyfile.NewTestDispenser(`metrics { disable_openmetrics }`)
	err = m.UnmarshalCaddyfile(d)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if !m.DisableOpenMetrics {
		t.Errorf("DisableOpenMetrics should've been true: %v", m.DisableOpenMetrics)
	}

	m = &Metrics{}
	d = caddyfile.NewTestDispenser(`metrics { bogus }`)
	err = m.UnmarshalCaddyfile(d)
	if err == nil {
		t.Errorf("expected error: %v", err)
	}
}
