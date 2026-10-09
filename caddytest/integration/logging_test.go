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
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddytest"
)

// TestLoggerNamesCaseInsensitive loads a config whose logger_names key is
// mixed-case and asserts that a request with a differently-cased Host is
// written by the configured named logger.
func TestLoggerNamesCaseInsensitive(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "access.log")
	logFileJSON, err := json.Marshal(logFile)
	if err != nil {
		t.Fatal(err)
	}

	tester := caddytest.NewTester(t)
	// Load a config without the file logger on cleanup so the log file is
	// closed before t.TempDir removes it; Windows cant delete open files.
	t.Cleanup(func() {
		tester.InitServer(`{"admin": {"listen": "localhost:2999"}}`, "json")
	})
	// The config is JSON because the Caddyfile adapter already lowercases
	// site addresses, so it would never produce a mixed-case key.
	tester.InitServer(`{
		"admin": {"listen": "localhost:2999"},
		"logging": {
			"logs": {
				"mixed": {
					"writer": {"output": "file", "filename": `+string(logFileJSON)+`},
					"encoder": {"format": "json"},
					"include": ["http.log.access.mixed"]
				}
			}
		},
		"apps": {
			"http": {
				"http_port": 9080,
				"grace_period": 1,
				"servers": {
					"srv0": {
						"listen": [":9080"],
						"routes": [
							{"handle": [{"handler": "static_response", "body": "ok"}]}
						],
						"logs": {
							"logger_names": {"Mixed.Example.org": ["mixed"]}
						}
					}
				}
			}
		}
	}`, "json")

	req, err := http.NewRequest(http.MethodGet, "http://localhost:9080/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "MIXED.example.org"
	tester.AssertResponse(req, http.StatusOK, "ok")

	// the access log entry is written after the response, so poll for it
	var logs []byte
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		logs, err = os.ReadFile(logFile)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(bytes.NewReader(logs))
		for scanner.Scan() {
			var entry struct {
				Logger  string `json:"logger"`
				Request struct {
					Host string `json:"host"`
				} `json:"request"`
			}
			if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
				continue
			}
			if entry.Logger == "http.log.access.mixed" && entry.Request.Host == "MIXED.example.org" {
				return
			}
		}
	}
	t.Errorf("no access log entry from logger %q for host %q, got %q", "http.log.access.mixed", "MIXED.example.org", logs)
}
