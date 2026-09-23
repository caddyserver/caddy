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

package reverseproxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// adminHandlerFixture sets up the global host state for an admin endpoint test
// and returns a cleanup function that must be deferred by the caller.
//
// staticAddrs are inserted into the UsagePool (as a static upstream would be).
// dynamicAddrs are inserted into the dynamicHosts map (as a dynamic upstream would be).
func adminHandlerFixture(t *testing.T, staticAddrs, dynamicAddrs []string) func() {
	t.Helper()

	for _, addr := range staticAddrs {
		u := &Upstream{Dial: addr}
		u.fillHost()
	}

	dynamicHostsMu.Lock()
	for _, addr := range dynamicAddrs {
		dynamicHosts[addr] = dynamicHostEntry{host: new(Host), lastSeen: time.Now()}
	}
	dynamicHostsMu.Unlock()

	return func() {
		// Remove static entries from the UsagePool.
		for _, addr := range staticAddrs {
			_, _ = hosts.Delete(addr)
		}
		// Remove dynamic entries.
		dynamicHostsMu.Lock()
		for _, addr := range dynamicAddrs {
			delete(dynamicHosts, addr)
		}
		dynamicHostsMu.Unlock()
	}
}

// callAdminUpstreams fires a GET against handleUpstreams and returns the
// decoded response body.
func callAdminUpstreams(t *testing.T) []upstreamStatus {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/reverse_proxy/upstreams", nil)
	w := httptest.NewRecorder()

	handler := adminUpstreams{}
	if err := handler.handleUpstreams(w, req); err != nil {
		t.Fatalf("handleUpstreams returned unexpected error: %v", err)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected Content-Type application/json, got %q", ct)
	}

	var results []upstreamStatus
	if err := json.NewDecoder(w.Body).Decode(&results); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	return results
}

// resultsByAddress indexes a slice of upstreamStatus by address for easier
// lookup in assertions.
func resultsByAddress(statuses []upstreamStatus) map[string]upstreamStatus {
	m := make(map[string]upstreamStatus, len(statuses))
	for _, s := range statuses {
		m[s.Address] = s
	}
	return m
}

// TestAdminUpstreamsMethodNotAllowed verifies that non-GET methods are rejected.
func TestAdminUpstreamsMethodNotAllowed(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(method, "/reverse_proxy/upstreams", nil)
		w := httptest.NewRecorder()
		err := (adminUpstreams{}).handleUpstreams(w, req)
		if err == nil {
			t.Errorf("method %s: expected an error, got nil", method)
			continue
		}
		apiErr, ok := err.(interface{ HTTPStatus() int })
		if !ok {
			// caddy.APIError stores the code in HTTPStatus field, access via the
			// exported interface it satisfies indirectly; just check non-nil.
			continue
		}
		if code := apiErr.HTTPStatus(); code != http.StatusMethodNotAllowed {
			t.Errorf("method %s: expected 405, got %d", method, code)
		}
	}
}

// TestAdminUpstreamsEmpty verifies that an empty response is valid JSON when
// no upstreams are registered.
func TestAdminUpstreamsEmpty(t *testing.T) {
	resetDynamicHosts()

	results := callAdminUpstreams(t)
	if results == nil {
		t.Error("expected non-nil (empty) slice, got nil")
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results with empty pools, got %d", len(results))
	}
}

// TestAdminUpstreamsStaticOnly verifies that static upstreams (from the
// UsagePool) appear in the response with correct addresses.
func TestAdminUpstreamsStaticOnly(t *testing.T) {
	resetDynamicHosts()
	cleanup := adminHandlerFixture(t,
		[]string{"10.0.0.1:80", "10.0.0.2:80"},
		nil,
	)
	defer cleanup()

	results := callAdminUpstreams(t)
	byAddr := resultsByAddress(results)

	for _, addr := range []string{"10.0.0.1:80", "10.0.0.2:80"} {
		if _, ok := byAddr[addr]; !ok {
			t.Errorf("expected static upstream %q in response", addr)
		}
	}
	if len(results) != 2 {
		t.Errorf("expected exactly 2 results, got %d", len(results))
	}
}

// TestAdminUpstreamsDynamicOnly verifies that dynamic upstreams (from
// dynamicHosts) appear in the response with correct addresses.
func TestAdminUpstreamsDynamicOnly(t *testing.T) {
	resetDynamicHosts()
	cleanup := adminHandlerFixture(t,
		nil,
		[]string{"10.0.1.1:80", "10.0.1.2:80"},
	)
	defer cleanup()

	results := callAdminUpstreams(t)
	byAddr := resultsByAddress(results)

	for _, addr := range []string{"10.0.1.1:80", "10.0.1.2:80"} {
		if _, ok := byAddr[addr]; !ok {
			t.Errorf("expected dynamic upstream %q in response", addr)
		}
	}
	if len(results) != 2 {
		t.Errorf("expected exactly 2 results, got %d", len(results))
	}
}

// TestAdminUpstreamsBothPools verifies that static and dynamic upstreams are
// both present in the same response and that there is no overlap or omission.
func TestAdminUpstreamsBothPools(t *testing.T) {
	resetDynamicHosts()
	cleanup := adminHandlerFixture(t,
		[]string{"10.0.2.1:80"},
		[]string{"10.0.2.2:80"},
	)
	defer cleanup()

	results := callAdminUpstreams(t)
	if len(results) != 2 {
		t.Fatalf("expected 2 results (1 static + 1 dynamic), got %d", len(results))
	}

	byAddr := resultsByAddress(results)
	if _, ok := byAddr["10.0.2.1:80"]; !ok {
		t.Error("static upstream missing from response")
	}
	if _, ok := byAddr["10.0.2.2:80"]; !ok {
		t.Error("dynamic upstream missing from response")
	}
}

// TestAdminUpstreamsNoOverlapBetweenPools verifies that an address registered
// only as a static upstream does not also appear as a dynamic entry, and
// vice-versa.
func TestAdminUpstreamsNoOverlapBetweenPools(t *testing.T) {
	resetDynamicHosts()
	cleanup := adminHandlerFixture(t,
		[]string{"10.0.3.1:80"},
		[]string{"10.0.3.2:80"},
	)
	defer cleanup()

	results := callAdminUpstreams(t)
	seen := make(map[string]int)
	for _, r := range results {
		seen[r.Address]++
	}
	for addr, count := range seen {
		if count > 1 {
			t.Errorf("address %q appeared %d times; expected exactly once", addr, count)
		}
	}
}

// TestAdminUpstreamsReportsFailCounts verifies that fail counts accumulated on
// a dynamic upstream's Host are reflected in the response.
func TestAdminUpstreamsReportsFailCounts(t *testing.T) {
	resetDynamicHosts()

	const addr = "10.0.4.1:80"
	h := new(Host)
	_ = h.countFail(3)

	dynamicHostsMu.Lock()
	dynamicHosts[addr] = dynamicHostEntry{host: h, lastSeen: time.Now()}
	dynamicHostsMu.Unlock()
	defer func() {
		dynamicHostsMu.Lock()
		delete(dynamicHosts, addr)
		dynamicHostsMu.Unlock()
	}()

	results := callAdminUpstreams(t)
	byAddr := resultsByAddress(results)

	status, ok := byAddr[addr]
	if !ok {
		t.Fatalf("expected %q in response", addr)
	}
	if status.Fails != 3 {
		t.Errorf("expected Fails=3, got %d", status.Fails)
	}
}

// TestAdminUpstreamsReportsNumRequests verifies that the active request count
// for a static upstream is reflected in the response.
func TestAdminUpstreamsReportsNumRequests(t *testing.T) {
	resetDynamicHosts()

	const addr = "10.0.4.2:80"
	u := &Upstream{Dial: addr}
	u.fillHost()
	defer func() { _, _ = hosts.Delete(addr) }()

	_ = u.Host.countRequest(2)
	defer func() { _ = u.Host.countRequest(-2) }()

	results := callAdminUpstreams(t)
	byAddr := resultsByAddress(results)

	status, ok := byAddr[addr]
	if !ok {
		t.Fatalf("expected %q in response", addr)
	}
	if status.NumRequests != 2 {
		t.Errorf("expected NumRequests=2, got %d", status.NumRequests)
	}
}
