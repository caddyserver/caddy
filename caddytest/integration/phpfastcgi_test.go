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
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/fcgi"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

// startFakePHPFPM starts a FastCGI responder that reports the SCRIPT_FILENAME it
// was asked to execute, so a test can assert which script Caddy selected.
func startFakePHPFPM(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		_ = fcgi.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			env := fcgi.ProcessEnv(r)
			fmt.Fprintf(w, "SCRIPT_FILENAME=%s", env["SCRIPT_FILENAME"])
		}))
	}()

	return ln.Addr().String()
}

// A php_fastcgi route protected by a path matcher must not execute a script the
// matcher never evaluated. Path matchers judge the cleaned request path, so
// /admin.php/../../other.php is matched as /other.php and must not cause
// <root>/admin.php to be executed.
//
// `index off` is used so that php_fastcgi generates no rewrite route at all
// (fastcgi/caddyfile.go skips the redirect and try_files routes entirely). That
// rewrite is otherwise the only step that normalizes r.URL.Path before the
// transport reads it, so without this the test would be satisfied by the rewrite
// rather than by the transport, and would not cover the transport's own
// normalization.
func TestPHPFastCGIProtectedRouteIgnoresDotSegments(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "admin.php"), []byte("<?php // protected"), 0o644); err != nil {
		t.Fatalf("writing admin.php: %v", err)
	}

	backend := startFakePHPFPM(t)

	tester := caddytest.NewTester(t)
	tester.InitServer(fmt.Sprintf(`{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period  1ns
	}

	localhost:9080 {
		root * %s

		handle /admin* {
			basic_auth {
				alice $2a$04$wqmCpxiUKZl83bZKH.Xp0uFvNQoGz3HoBH3IxBwRMrKoCRfTmc3KK
			}
			php_fastcgi %s {
				index off
			}
		}

		handle {
			php_fastcgi %s {
				index off
			}
		}
	}
	`, root, backend, backend), "caddyfile")

	get := func(t *testing.T, uri string, basicAuth bool) (int, string) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, "http://localhost:9080"+uri, nil)
		if err != nil {
			t.Fatalf("building request: %v", err)
		}
		if basicAuth {
			req.SetBasicAuth("alice", "test-password")
		}
		resp, err := tester.Client.Do(req)
		if err != nil {
			t.Fatalf("requesting %q: %v", uri, err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("reading body: %v", err)
		}
		return resp.StatusCode, string(body)
	}

	// The gate works for a direct request...
	if code, _ := get(t, "/admin.php", false); code != http.StatusUnauthorized {
		t.Fatalf("GET /admin.php without credentials: expected 401, got %d", code)
	}

	// ...and valid credentials reach the protected script, which proves the route
	// is wired up and the 401 above is the gate rather than a misconfiguration.
	code, body := get(t, "/admin.php", true)
	if code != http.StatusOK {
		t.Fatalf("GET /admin.php with credentials: expected 200, got %d", code)
	}
	if !strings.HasSuffix(body, filepath.Join(root, "admin.php")) {
		t.Fatalf("authenticated request should execute admin.php, got %q", body)
	}

	// The bypass: every path matcher sees /other.php, so the /admin* gate does not
	// fire. The transport must not then select admin.php.
	for _, payload := range []string{
		"/admin.php/../../other.php",
		"/admin.php/../other.php",
		"/admin.php/..%2f..%2fother.php",
		"/admin.php/%2e%2e/other.php",
	} {
		t.Run(payload, func(t *testing.T) {
			_, body := get(t, payload, false)
			if strings.Contains(body, "admin.php") {
				t.Fatalf("unauthenticated request %q selected the protected script: %s", payload, body)
			}
		})
	}
}

// The php_fastcgi directory redirect must stay on the requesting origin. Its
// matcher judges the cleaned request path, so /%2Fevil.com%2F..%2Fsub is matched
// as /sub and resolves to <root>/sub/index.php, but the Location header used to
// be built from the raw original path and came out as //evil.com/../sub/, which
// browsers treat as a scheme-relative URL to another host. The relative
// reference is built from the escaped original segment, so names with reserved
// or non-ASCII characters must still round-trip to the same directory.
func TestPHPFastCGIDirectoryRedirectStaysOnOrigin(t *testing.T) {
	dirs := []string{"sub", "a b", "a#b", "50%", "a;b", "café", "x/sub"}
	if runtime.GOOS != "windows" {
		dirs = append(dirs, "a?b", "a:b")
	}
	root := t.TempDir()
	for _, dir := range dirs {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(dir)), 0o755); err != nil {
			t.Fatalf("creating %s: %v", dir, err)
		}
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(dir), "index.php"), []byte("<?php // index"), 0o644); err != nil {
			t.Fatalf("writing %s/index.php: %v", dir, err)
		}
	}

	tester := caddytest.NewTester(t)
	tester.InitServer(fmt.Sprintf(`{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period  1ns
	}

	localhost:9080 {
		root * %s
		php_fastcgi 127.0.0.1:9
	}
	`, root), "caddyfile")

	tests := []struct {
		uri  string
		want string
	}{
		{uri: "/sub", want: "/sub/"},
		{uri: "/sub?a=1", want: "/sub/?a=1"},
		{uri: "/%2Fevil.com%2F..%2Fsub", want: "/%2Fevil.com%2F..%2Fsub/"},
		{uri: "/%5Cevil.com%2F..%2Fsub", want: "/%5Cevil.com%2F..%2Fsub/"},
		{uri: "/a%20b", want: "/a%20b/"},
		{uri: "/a%23b", want: "/a%23b/"},
		{uri: "/50%25", want: "/50%25/"},
		{uri: "/a;b", want: "/a;b/"},
		{uri: "/caf%C3%A9", want: "/caf%C3%A9/"},
		{uri: "/x%2Fsub", want: "/x%2Fsub/"},
	}
	if runtime.GOOS != "windows" {
		tests = append(tests,
			struct{ uri, want string }{uri: "/a%3Fb", want: "/a%3Fb/"},
			struct{ uri, want string }{uri: "/a:b", want: "/a:b/"},
		)
	}
	for _, tc := range tests {
		resp := tester.AssertRedirect("http://localhost:9080"+tc.uri, "http://localhost:9080"+tc.want, http.StatusPermanentRedirect)
		if resp == nil {
			continue
		}
		loc := resp.Header.Get("Location")
		// a Location beginning with // or /\ is scheme-relative to browsers
		if strings.HasPrefix(loc, "//") || strings.HasPrefix(loc, `/\`) {
			t.Errorf("requesting %q: Location %q is not origin-relative", tc.uri, loc)
		}
		for i := 0; i < len(loc); i++ {
			if loc[i] < 0x21 || loc[i] > 0x7e {
				t.Errorf("requesting %q: Location %q contains an unescaped byte %#x", tc.uri, loc, loc[i])
				break
			}
		}
	}
}
