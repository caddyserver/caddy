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
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyevents"
)

// newActiveHandler builds a minimal Handler with active health checks
// configured against addr, provisions its single upstream, and returns
// the handler, its upstream, and a cancel func the caller must defer.
func newActiveHandler(t *testing.T, addr, uri string, fails int) (*Handler, *Upstream, context.CancelFunc) {
	t.Helper()
	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})

	eventsApp := new(caddyevents.App)
	if err := eventsApp.Provision(caddyCtx); err != nil {
		t.Fatalf("provisioning events app: %v", err)
	}

	u := &Upstream{Dial: addr}
	h := &Handler{
		ctx:       caddyCtx,
		logger:    zap.NewNop(),
		events:    eventsApp,
		Upstreams: UpstreamPool{u},
		HealthChecks: &HealthChecks{
			Active: &ActiveHealthChecks{
				URI:   uri,
				Fails: fails,
			},
		},
	}
	h.provisionUpstream(u, false)
	if err := h.HealthChecks.Active.Provision(caddyCtx, h); err != nil {
		t.Fatalf("provisioning active health checks: %v", err)
	}
	return h, u, cancel
}

// runActiveHealthCheck synchronously performs one active health check round
// for the handler's upstream (what doActiveHealthCheckForAllHosts does per
// tick, minus the goroutine).
func runActiveHealthCheck(t *testing.T, h *Handler, u *Upstream) {
	t.Helper()
	dialInfo, err := u.fillDialInfo(caddy.NewReplacer())
	if err != nil {
		t.Fatalf("filling dial info: %v", err)
	}
	if err := h.doActiveHealthCheck(dialInfo, dialInfo.Address, u.Dial, u); err != nil {
		t.Fatalf("active health check: %v", err)
	}
}

// drainHostsPool removes every entry from the global static host pool,
// deleting each exactly as many times as it was stored so the pool is
// empty for subsequent tests.
func drainHostsPool() {
	var keys []any
	hosts.Range(func(key, _ any) bool {
		keys = append(keys, key)
		return true
	})
	for _, key := range keys {
		if refs, ok := hosts.References(key); ok {
			for range refs {
				_, _ = hosts.Delete(key)
			}
		}
	}
}

// TestActiveHealthChecksSameAddressDifferentChecksAreIndependent is a
// regression test for https://github.com/caddyserver/caddy/issues/7870:
// two handlers that dial the same upstream address but run different
// active health checks (different health_uri) must keep independent
// health state. Before the fix, the consecutive pass/fail counters lived
// on the Host, which is shared by dial address, so both checkers mutated
// the same counters: one vhost's failing probes could push the other
// vhost's upstream over its own fails threshold and knock it out of that
// vhost's data path.
func TestActiveHealthChecksSameAddressDifferentChecksAreIndependent(t *testing.T) {
	resetDynamicHosts()
	defer drainHostsPool()

	// one backend node serving two vhosts: vhost A's health endpoint is
	// down, vhost B's is up (except for one transient failure below)
	var vhostBUp atomic.Bool
	vhostBUp.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/vhost-a/health":
			w.WriteHeader(http.StatusServiceUnavailable)
		case "/vhost-b/health":
			if vhostBUp.Load() {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusServiceUnavailable)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	hA, uA, cancelA := newActiveHandler(t, addr, "/vhost-a/health", 5)
	defer cancelA()
	hB, uB, cancelB := newActiveHandler(t, addr, "/vhost-b/health", 3)
	defer cancelB()

	// vhost A's checker observes two consecutive failures — below its own
	// fails=5 threshold, so these must affect no one's health status
	runActiveHealthCheck(t, hA, uA)
	runActiveHealthCheck(t, hA, uA)

	// vhost B's checker observes a single transient failure; B tolerates
	// up to fails=3 consecutive failures, so it must remain healthy
	vhostBUp.Store(false)
	runActiveHealthCheck(t, hB, uB)

	if !uA.Healthy() {
		t.Errorf("vhost A's upstream should still be healthy after 2 of 5 tolerated failures")
	}
	if !uB.Healthy() {
		t.Errorf("vhost B's upstream was marked unhealthy after a single failed probe (fails=3); " +
			"its health state was polluted by vhost A's health check against the same address")
	}
}

// TestActiveHealthCheckBodyKeepsUnknownPlaceholders is a regression test for
// https://github.com/caddyserver/caddy/issues/7021: an active health check
// body is user-supplied and is commonly JSON, so its braces must not be read
// as placeholders and blanked. Only globals are available to this replacer, so
// replacing everything sent an empty body for any JSON health_request_body.
func TestActiveHealthCheckBodyKeepsUnknownPlaceholders(t *testing.T) {
	resetDynamicHosts()
	defer drainHostsPool()

	const jsonBody = `{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}`

	var gotBody atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading request body: %v", err)
		}
		gotBody.Store(string(body))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	h, u, cancel := newActiveHandler(t, addr, "/health", 1)
	defer cancel()

	h.HealthChecks.Active.Body = jsonBody

	runActiveHealthCheck(t, h, u)

	if got, want := gotBody.Load(), jsonBody; got != want {
		t.Errorf("health check body = %q, want %q", got, want)
	}
}

// TestActiveHealthCheckBodyStillReplacesKnownPlaceholders guards the other
// direction: switching to ReplaceKnown must not stop real placeholders from
// being replaced.
func TestActiveHealthCheckBodyStillReplacesKnownPlaceholders(t *testing.T) {
	resetDynamicHosts()
	defer drainHostsPool()

	t.Setenv("CADDY_TEST_HEALTH_TOKEN", "s3cret")

	var gotBody atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading request body: %v", err)
		}
		gotBody.Store(string(body))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	h, u, cancel := newActiveHandler(t, addr, "/health", 1)
	defer cancel()

	h.HealthChecks.Active.Body = `{"token":"{env.CADDY_TEST_HEALTH_TOKEN}"}`

	runActiveHealthCheck(t, h, u)

	if got, want := gotBody.Load(), `{"token":"s3cret"}`; got != want {
		t.Errorf("health check body = %q, want %q", got, want)
	}
}
