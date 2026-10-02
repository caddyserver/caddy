// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddyhttp

import (
	"crypto/tls"
	"testing"

	"go.uber.org/zap/zapcore"
)

func TestLoggableTLSConnStateCurve(t *testing.T) {
	tests := []struct {
		name      string
		curveID   tls.CurveID
		wantCurve bool
		wantVal   uint16
	}{
		{
			name:      "X25519MLKEM768",
			curveID:   tls.X25519MLKEM768,
			wantCurve: true,
			wantVal:   uint16(tls.X25519MLKEM768),
		},
		{
			name:      "X25519",
			curveID:   tls.X25519,
			wantCurve: true,
			wantVal:   uint16(tls.X25519),
		},
		{
			name:      "P256",
			curveID:   tls.CurveP256,
			wantCurve: true,
			wantVal:   uint16(tls.CurveP256),
		},
		{
			name:      "zero omitted",
			curveID:   0,
			wantCurve: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			enc := zapcore.NewMapObjectEncoder()
			state := LoggableTLSConnState{CurveID: tc.curveID}
			if err := state.MarshalLogObject(enc); err != nil {
				t.Fatalf("MarshalLogObject: %v", err)
			}
			val, ok := enc.Fields["curve"]
			if tc.wantCurve {
				if !ok {
					t.Fatalf("expected curve field to be logged")
				}
				got, ok := val.(uint16)
				if !ok {
					t.Fatalf("curve field type = %T, want uint16", val)
				}
				if got != tc.wantVal {
					t.Fatalf("curve = %d, want %d", got, tc.wantVal)
				}
			} else if ok {
				t.Fatalf("expected curve field to be omitted for CurveID 0, got %v", val)
			}
		})
	}
}
