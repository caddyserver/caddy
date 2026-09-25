package caddyhttp

import (
	"crypto/tls"
	"testing"

	"go.uber.org/zap/zapcore"
)

func TestLoggableTLSConnStateCurve(t *testing.T) {
	for _, tc := range []struct {
		name  string
		curve tls.CurveID
	}{
		{name: "hybrid post-quantum", curve: tls.X25519MLKEM768},
		{name: "classical", curve: tls.X25519},
		{name: "none negotiated", curve: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			enc := zapcore.NewMapObjectEncoder()
			state := LoggableTLSConnState(tls.ConnectionState{Version: tls.VersionTLS13, CurveID: tc.curve})
			if err := state.MarshalLogObject(enc); err != nil {
				t.Fatalf("MarshalLogObject: %v", err)
			}
			got, ok := enc.Fields["curve"]
			if tc.curve == 0 {
				if ok {
					t.Errorf("expected no curve field when none was negotiated, got %v", got)
				}
				return
			}
			if !ok {
				t.Fatalf("expected a curve field, got fields %v", enc.Fields)
			}
			if got != uint16(tc.curve) {
				t.Errorf("curve = %v, want %d", got, uint16(tc.curve))
			}
		})
	}
}
