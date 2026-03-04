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
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

// TestForwardAuthCopyHeadersStripsClientHeaders is a regression test for the
// header injection vulnerability in forward_auth copy_headers.
//
// When the auth service returns 200 OK without one of the copy_headers headers,
// the MatchNot guard skips the Set operation. Before this fix, the original
// client-supplied header survived unchanged into the backend request, allowing
// privilege escalation with only a valid (non-privileged) bearer token. After
// the fix, an unconditional delete route runs first, so the backend always
// sees an absent header rather than the attacker-supplied value.
func TestForwardAuthCopyHeadersStripsClientHeaders(t *testing.T) {
	// Mock auth service: accepts any Bearer token, returns 200 OK with NO
	// identity headers. This is the stateless JWT validator pattern that
	// triggers the vulnerability.
	authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer authSrv.Close()

	// Mock backend: records the identity headers it receives. A real application
	// would use X-User-Id / X-User-Role to make authorization decisions.
	type received struct{ userID, userRole string }
	var (
		mu   sync.Mutex
		last received
	)
	backendSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		last = received{
			userID:   r.Header.Get("X-User-Id"),
			userRole: r.Header.Get("X-User-Role"),
		}
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer backendSrv.Close()

	authAddr := strings.TrimPrefix(authSrv.URL, "http://")
	backendAddr := strings.TrimPrefix(backendSrv.URL, "http://")

	tester := caddytest.NewTester(t)
	tester.InitServer(fmt.Sprintf(`
	{
		skip_install_trust
		admin localhost:2999
		http_port 9080
		https_port 9443
		grace_period 1ns
	}
	http://localhost:9080 {
		forward_auth %s {
			uri /
			copy_headers X-User-Id X-User-Role
		}
		reverse_proxy %s
	}
	`, authAddr, backendAddr), "caddyfile")

	// Case 1: no token. Auth must still reject the request even when the client
	// includes identity headers. This confirms the auth check is not bypassed.
	req, _ := http.NewRequest(http.MethodGet, "http://localhost:9080/", nil)
	req.Header.Set("X-User-Id", "injected")
	req.Header.Set("X-User-Role", "injected")
	resp := tester.AssertResponseCode(req, http.StatusUnauthorized)
	resp.Body.Close()

	// Case 2: valid token, no injected headers. The backend should see absent
	// identity headers (the auth service never returns them).
	req, _ = http.NewRequest(http.MethodGet, "http://localhost:9080/", nil)
	req.Header.Set("Authorization", "Bearer token123")
	tester.AssertResponse(req, http.StatusOK, "ok")
	mu.Lock()
	gotID, gotRole := last.userID, last.userRole
	mu.Unlock()
	if gotID != "" {
		t.Errorf("baseline: X-User-Id should be absent, got %q", gotID)
	}
	if gotRole != "" {
		t.Errorf("baseline: X-User-Role should be absent, got %q", gotRole)
	}

	// Case 3 (the security regression): valid token plus forged identity headers.
	// The fix must strip those values so the backend never sees them.
	req, _ = http.NewRequest(http.MethodGet, "http://localhost:9080/", nil)
	req.Header.Set("Authorization", "Bearer token123")
	req.Header.Set("X-User-Id", "admin")        // forged
	req.Header.Set("X-User-Role", "superadmin") // forged
	tester.AssertResponse(req, http.StatusOK, "ok")
	mu.Lock()
	gotID, gotRole = last.userID, last.userRole
	mu.Unlock()
	if gotID != "" {
		t.Errorf("injection: X-User-Id must be stripped, got %q", gotID)
	}
	if gotRole != "" {
		t.Errorf("injection: X-User-Role must be stripped, got %q", gotRole)
	}
}

// TestForwardAuthCopyHeadersAuthResponseWins verifies that when the auth
// service does include a copy_headers header in its response, that value
// is forwarded to the backend and takes precedence over any client-supplied
// value for the same header.
func TestForwardAuthCopyHeadersAuthResponseWins(t *testing.T) {
	const wantUserID = "service-user-42"
	const wantUserRole = "editor"

	// Auth service: accepts bearer token and sets identity headers.
	authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			w.Header().Set("X-User-Id", wantUserID)
			w.Header().Set("X-User-Role", wantUserRole)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer authSrv.Close()

	type received struct{ userID, userRole string }
	var (
		mu   sync.Mutex
		last received
	)
	backendSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		last = received{
			userID:   r.Header.Get("X-User-Id"),
			userRole: r.Header.Get("X-User-Role"),
		}
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer backendSrv.Close()

	authAddr := strings.TrimPrefix(authSrv.URL, "http://")
	backendAddr := strings.TrimPrefix(backendSrv.URL, "http://")

	tester := caddytest.NewTester(t)
	tester.InitServer(fmt.Sprintf(`
	{
		skip_install_trust
		admin localhost:2999
		http_port 9080
		https_port 9443
		grace_period 1ns
	}
	http://localhost:9080 {
		forward_auth %s {
			uri /
			copy_headers X-User-Id X-User-Role
		}
		reverse_proxy %s
	}
	`, authAddr, backendAddr), "caddyfile")

	// The client sends forged headers; the auth service overrides them with
	// its own values. The backend must receive the auth service values.
	req, _ := http.NewRequest(http.MethodGet, "http://localhost:9080/", nil)
	req.Header.Set("Authorization", "Bearer token123")
	req.Header.Set("X-User-Id", "forged-id")   // must be overwritten
	req.Header.Set("X-User-Role", "forged-role") // must be overwritten
	tester.AssertResponse(req, http.StatusOK, "ok")

	mu.Lock()
	gotID, gotRole := last.userID, last.userRole
	mu.Unlock()
	if gotID != wantUserID {
		t.Errorf("X-User-Id: want %q, got %q", wantUserID, gotID)
	}
	if gotRole != wantUserRole {
		t.Errorf("X-User-Role: want %q, got %q", wantUserRole, gotRole)
	}
}
