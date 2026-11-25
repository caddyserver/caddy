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
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

func TestAccessLogExternalRotation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("cannot rename this open file on Windows")
	}
	filename := filepath.Join(t.TempDir(), "access.log")
	archive := filename + ".1"
	config := fmt.Sprintf(`{
	admin localhost:2999
}

http://localhost:9080 {
	respond "ok"
	log {
		format json
		output file %q {
			roll_disabled
		}
	}
}
`, filename)
	tester := caddytest.NewTester(t)
	tester.InitServer(config, "caddyfile")
	t.Cleanup(func() { tester.InitServer(`{"admin":{"listen":"localhost:2999"}}`, "json") })
	requestAndCheck := func(uri, file string) {
		t.Helper()
		tester.AssertGetResponse("http://localhost:9080"+uri, http.StatusOK, "ok")
		// Access logging may finish after the response reaches the client.
		marker := []byte(`"uri":"` + uri + `"`)
		for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			data, err := os.ReadFile(file)
			if err == nil && bytes.Count(data, marker) == 1 {
				return
			}
		}
		t.Fatalf("expected one entry for %s in %s", uri, file)
	}
	reload := func(candidate string, force bool, wantStatus int) {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, "http://localhost:2999/load", strings.NewReader(candidate))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "text/caddyfile")
		if force {
			req.Header.Set("Cache-Control", "must-revalidate")
		}
		resp := tester.AssertResponseCode(req, wantStatus)
		resp.Body.Close()
	}
	requestAndCheck("/before", filename)
	if err := os.Rename(filename, archive); err != nil {
		t.Fatal(err)
	}
	reload(config, false, http.StatusOK)
	requestAndCheck("/unchanged", archive)
	reload(config, true, http.StatusOK)
	requestAndCheck("/after", filename)
	data, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(`"uri":"/after"`)) {
		t.Fatal("post-reload entry also reached archive")
	}

	// Some rotators create the replacement themselves.
	secondArchive := filename + ".2"
	if err := os.Rename(filename, secondArchive); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, []byte("existing\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// An app start failure after preparing the replacement must leave the
	// active logger writing to the archive.
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	broken := config + fmt.Sprintf("\nhttp://%s {\n respond busy\n}\n", listener.Addr())
	reload(broken, false, http.StatusBadRequest)
	requestAndCheck("/failed", secondArchive)
	reload(config, true, http.StatusOK)
	requestAndCheck("/retry", filename)
	data, err = os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(data, []byte("existing\n")) {
		t.Fatal("reopen truncated the replacement file")
	}
}
