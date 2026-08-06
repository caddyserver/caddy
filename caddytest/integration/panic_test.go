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

package integration

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	// register the standard modules (http app, file log writer, etc.)
	_ "github.com/caddyserver/caddy/v2/modules/standard"
)

const (
	// panicTestHandlerID is the module ID of the test-only handler that panics.
	panicTestHandlerID = "http.handlers.panic_test"
	// panicLogPrefix is the prefix Go's net/http server writes to
	// http.Server.ErrorLog when it recovers a handler panic. It mirrors the
	// unexported production constant caddyhttp.stdlibLogPrefixPanic.
	panicLogPrefix = "http: panic serving"
	// panicErrorLevel is the zap level string the JSON encoder emits for
	// entries logged at error level.
	panicErrorLevel = "error"
	// panicLogFilename is the log file the booted server writes to.
	panicLogFilename = "panic.log"
	// panicListenAddr is the HTTP listener for the panic route.
	panicListenAddr = ":9080"
	// panicRequestURL hits the panic route.
	panicRequestURL = "http://localhost:9080/"
	// panicLogPollInterval is how often the test re-reads the log file while
	// waiting for the panic entry to be flushed to disk.
	panicLogPollInterval = 50 * time.Millisecond
	// panicLogPollTimeout bounds how long the test waits for the entry.
	panicLogPollTimeout = 5 * time.Second
)

// panicHandler is a test-only HTTP handler module that panics in ServeHTTP
// with a non-ErrAbortHandler value, so Go's net/http server recovers it and
// writes an "http: panic serving" line to http.Server.ErrorLog.
type panicHandler struct{}

func (panicHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  panicTestHandlerID,
		New: func() caddy.Module { return new(panicHandler) },
	}
}

func (panicHandler) ServeHTTP(http.ResponseWriter, *http.Request, caddyhttp.Handler) error {
	panic("boom from panic_test handler")
}

func init() {
	caddy.RegisterModule(panicHandler{})
}

// TestHandlerPanicLogsAtError boots a real Caddy HTTP server whose route panics
// while serving a request, and asserts that the recovered panic surfaces in
// Caddy's structured logs at ERROR level (so it stays visible at the default
// log level). Booting exercises the App.Start() server-boot wiring that routes
// http.Server.ErrorLog through Caddy's structured logger. Regression test for
// https://github.com/caddyserver/caddy/issues/7923.
func TestHandlerPanicLogsAtError(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), panicLogFilename)

	// Boot a real Caddy instance. caddy.Run provisions and calls App.Start
	// synchronously, so the panic-log wiring runs before we send the request.
	config := `{
		"admin": {"disabled": true},
		"logging": {
			"logs": {
				"default": {
					"writer": {"output": "file", "filename": "` + logPath + `"},
					"encoder": {"format": "json"},
					"level": "DEBUG"
				}
			}
		},
		"apps": {
			"http": {
				"grace_period": 1,
				"servers": {
					"srv0": {
						"listen": ["` + panicListenAddr + `"],
						"automatic_https": {"disable": true},
						"routes": [
							{"handle": [{"handler": "panic_test"}]}
						]
					}
				}
			}
		}
	}`
	if err := caddy.Load([]byte(config), true); err != nil {
		t.Fatalf("failed to load caddy config: %v", err)
	}
	t.Cleanup(func() {
		if err := caddy.Stop(); err != nil {
			t.Errorf("failed to stop caddy: %v", err)
		}
	})

	// The panic aborts the connection, so the client sees an error; that's
	// expected. We only care that the server logged the panic.
	resp, err := http.Get(panicRequestURL)
	if err == nil {
		resp.Body.Close()
	}

	if !waitForPanicLog(t, logPath) {
		t.Fatalf("did not find an error-level %q entry in %s", panicLogPrefix, logPath)
	}
}

// waitForPanicLog polls the log file until it contains a JSON entry logged at
// error level whose message begins with the net/http panic prefix, or the
// timeout elapses.
func waitForPanicLog(t *testing.T, logPath string) bool {
	t.Helper()
	deadline := time.Now().Add(panicLogPollTimeout)
	for time.Now().Before(deadline) {
		if scanForPanicEntry(t, logPath) {
			return true
		}
		time.Sleep(panicLogPollInterval)
	}
	return false
}

func scanForPanicEntry(t *testing.T, logPath string) bool {
	t.Helper()
	f, err := os.Open(logPath)
	if err != nil {
		// The file may not exist yet before the first log line is written.
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var entry struct {
			Level string `json:"level"`
			Msg   string `json:"msg"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}
		if entry.Level == panicErrorLevel && strings.HasPrefix(entry.Msg, panicLogPrefix) {
			return true
		}
	}
	return false
}
