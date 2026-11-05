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
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestStopWaitsForPreviousConfiguration(t *testing.T) {
	for _, http2 := range []bool{false, true} {
		for _, grace := range []time.Duration{0, 5 * time.Second} {
			t.Run(fmt.Sprintf("http2=%t/grace=%s", http2, grace), func(t *testing.T) {
				previous, response, release := appWithPendingResponse(t, http2)
				previous.GracePeriod = caddy.Duration(grace)
				if err := previous.stop(false); err != nil {
					t.Fatal(err)
				}

				current := &App{logger: zap.NewNop()}
				stopped := make(chan error, 1)
				go func() { stopped <- current.stop(true) }()
				select {
				case err := <-stopped:
					t.Fatalf("termination returned while the previous response was active: %v", err)
				case <-time.After(50 * time.Millisecond):
				}

				release()
				body, err := io.ReadAll(response.Body)
				if err != nil {
					t.Fatal(err)
				}
				if string(body) != "before\nafter\n" {
					t.Fatalf("unexpected response body: %q", body)
				}
				select {
				case err := <-stopped:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("termination did not finish after the previous response completed")
				}
			})
		}
	}
}

func TestStopPreviousConfigurationGracePeriod(t *testing.T) {
	previous, response, release := appWithPendingResponse(t, false)
	if err := previous.stop(false); err != nil {
		t.Fatal(err)
	}

	current := &App{GracePeriod: caddy.Duration(50 * time.Millisecond), logger: zap.NewNop()}
	stopped := make(chan error, 1)
	start := time.Now()
	go func() { stopped <- current.stop(true) }()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("termination ignored its grace period while waiting for the previous configuration")
	}
	if elapsed := time.Since(start); elapsed < time.Duration(current.GracePeriod) {
		t.Errorf("termination returned after %s, before its grace period expired", elapsed)
	}

	release()
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		t.Fatal(err)
	}
}

func appWithPendingResponse(t *testing.T, http2 bool) (*App, *http.Response, func()) {
	t.Helper()

	released := make(chan struct{})
	release := sync.OnceFunc(func() { close(released) })
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "before")
		http.NewResponseController(w).Flush()
		select {
		case <-released:
			fmt.Fprintln(w, "after")
		case <-r.Context().Done():
		}
	}))
	server.EnableHTTP2 = http2
	server.StartTLS()
	t.Cleanup(server.Close)
	t.Cleanup(release)

	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { response.Body.Close() })
	if http2 && response.ProtoMajor != 2 {
		t.Fatalf("expected HTTP/2, got %s", response.Proto)
	}
	app := &App{
		Servers: map[string]*Server{"test": {server: server.Config}},
		logger:  zap.NewNop(),
	}
	t.Cleanup(func() {
		release()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		server.Config.Shutdown(ctx)
	})
	return app, response, release
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
