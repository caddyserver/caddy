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
	for _, tc := range []struct {
		curve    tls.CurveID
		expected any
	}{
		{curve: tls.X25519MLKEM768, expected: uint16(4588)},
		{curve: tls.X25519, expected: uint16(29)},
		{curve: 0, expected: nil},
	} {
		enc := zapcore.NewMapObjectEncoder()
		if err := LoggableTLSConnState(tls.ConnectionState{CurveID: tc.curve}).MarshalLogObject(enc); err != nil {
			t.Fatalf("curve %d: unexpected error: %v", tc.curve, err)
		}
		if actual := enc.Fields["curve"]; actual != tc.expected {
			t.Errorf("curve %d: expected %v (%T), got %v (%T)", tc.curve, tc.expected, tc.expected, actual, actual)
		}
	}
}
