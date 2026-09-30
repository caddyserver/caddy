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
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/caddyserver/caddy/v2"
)

func TestListenerIncludesAddress(t *testing.T) {
	tests := []struct {
		name     string
		listener string
		target   string
		want     bool
	}{
		{name: "exact", listener: "localhost:2019", target: "localhost:2019", want: true},
		{name: "port range", listener: "localhost:2010-2020", target: "localhost:2019", want: true},
		{name: "different host", listener: "127.0.0.1:2019", target: "localhost:2019"},
		{name: "different network", listener: "udp/localhost:2019", target: "localhost:2019"},
		{name: "different port", listener: "localhost:2020", target: "localhost:2019"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			listener, err := caddy.ParseNetworkAddress(test.listener)
			if err != nil {
				t.Fatal(err)
			}
			target, err := caddy.ParseNetworkAddress(test.target)
			if err != nil {
				t.Fatal(err)
			}
			if got := listenerIncludesAddress(listener, target); got != test.want {
				t.Fatalf("listenerIncludesAddress() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestValidateWarnsOnAdminListener(t *testing.T) {
	adminAddr := caddy.NetworkAddress{Network: "tcp", Host: "localhost", StartPort: 2019, EndPort: 2019}

	for _, test := range []struct {
		name         string
		listen       string
		adminEnabled bool
		wantWarnings int
	}{
		{name: "matching address", listen: "localhost:2019", adminEnabled: true, wantWarnings: 1},
		{name: "matching port range", listen: "localhost:2010-2020", adminEnabled: true, wantWarnings: 1},
		{name: "different address", listen: "localhost:2020", adminEnabled: true},
		{name: "admin disabled", listen: "localhost:2019"},
	} {
		t.Run(test.name, func(t *testing.T) {
			core, logs := observer.New(zapcore.WarnLevel)
			app := App{
				logger:       zap.New(core),
				adminAddr:    adminAddr,
				adminEnabled: test.adminEnabled,
				Servers: map[string]*Server{
					"test": {Listen: []string{test.listen}},
				},
			}

			if err := app.Validate(); err != nil {
				t.Fatal(err)
			}
			if got := logs.Len(); got != test.wantWarnings {
				t.Fatalf("warnings = %d, want %d", got, test.wantWarnings)
			}
		})
	}
}

// TestServerErrorLoggerLevels verifies that recovered net/http handler panics
// written to http.Server.ErrorLog surface at ERROR level (so they're visible
// at the default log level), while other standard library server messages stay
// at DEBUG. Regression test for #7923.
func TestServerErrorLoggerLevels(t *testing.T) {
	for _, tc := range []struct {
		name      string
		message   string
		wantLevel zapcore.Level
	}{
		{
			name:      "recovered handler panic logs at error",
			message:   "http: panic serving 127.0.0.1:12345: boom\ngoroutine 1 [running]:\nmain.handler()",
			wantLevel: zapcore.ErrorLevel,
		},
		{
			name:      "other server message logs at debug",
			message:   "http: TLS handshake error from 127.0.0.1:12345: EOF",
			wantLevel: zapcore.DebugLevel,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			core, logs := observer.New(zapcore.DebugLevel)
			serverLogger := serverErrorLogger(zap.New(core))

			serverLogger.Print(tc.message)

			entries := logs.All()
			if len(entries) != 1 {
				t.Fatalf("expected exactly 1 log entry, got %d", len(entries))
			}
			got := entries[0]
			if got.Level != tc.wantLevel {
				t.Errorf("expected level %s, got %s", tc.wantLevel, got.Level)
			}
			if got.Message != tc.message {
				t.Errorf("expected message %q, got %q", tc.message, got.Message)
			}
		})
	}
}
