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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
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
// however entries are keyed, deleting each exactly as many times as it
// was stored so the pool is empty for subsequent tests.
func drainHostsPool() {
	var keys []any
	hosts.Range(func(key, _ any) bool {
		keys = append(keys, key)
		return true
	})
	for _, key := range keys {
		if refs, ok := hosts.References(key); ok {
			for i := 0; i < refs; i++ {
				_, _ = hosts.Delete(key)
			}
		}
	}
}

// TestActiveHealthChecksSameAddressDifferentChecksAreIndependent is a
// regression test for https://github.com/caddyserver/caddy/issues/7870:
// two handlers that dial the same upstream address but run different
// active health checks (different health_uri) must keep independent
// health state. Before the fix, health state was keyed only by dial
// address, so both checkers mutated the same consecutive-fail counter:
// one vhost's failing probes could push the other vhost's upstream over
// its own fails threshold and knock it out of that vhost's data path.
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

// TestUpstreamsHealthyMetricSeparatesHealthChecks verifies that the
// caddy_reverse_proxy_upstreams_healthy metric carries the health_check
// discriminator: two handlers dialing the same address with different
// active health checks must write two DISTINCT series reflecting their
// own health state, not race last-writer-wins on one series keyed by
// address alone.
func TestUpstreamsHealthyMetricSeparatesHealthChecks(t *testing.T) {
	resetDynamicHosts()
	defer drainHostsPool()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/vhost-a/health":
			w.WriteHeader(http.StatusServiceUnavailable)
		case "/vhost-b/health":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	// vhost A tolerates a single failure, so one failing round marks it
	// unhealthy; vhost B stays healthy throughout
	hA, uA, cancelA := newActiveHandler(t, addr, "/vhost-a/health", 1)
	defer cancelA()
	hB, uB, cancelB := newActiveHandler(t, addr, "/vhost-b/health", 1)
	defer cancelB()

	fpA := hostKeyFingerprint(uA.hostKey)
	fpB := hostKeyFingerprint(uB.hostKey)
	if fpA == "" || fpB == "" || fpA == fpB {
		t.Fatalf("expected distinct non-empty fingerprints, got %q and %q", fpA, fpB)
	}

	runActiveHealthCheck(t, hA, uA)
	runActiveHealthCheck(t, hB, uB)
	if uA.Healthy() || !uB.Healthy() {
		t.Fatalf("precondition: want A unhealthy and B healthy, got A=%v B=%v",
			uA.Healthy(), uB.Healthy())
	}

	// both updaters write their state; before the health_check label this
	// was one shared series and the last writer won
	upA := newMetricsUpstreamsHealthyUpdater(hA, hA.ctx)
	upB := newMetricsUpstreamsHealthyUpdater(hB, hB.ctx)
	upA.update()
	upB.update()

	gaugeFor := func(fp string) float64 {
		g, err := reverseProxyMetrics.upstreamsHealthy.GetMetricWith(
			prometheus.Labels{"upstream": addr, "health_check": fp})
		if err != nil {
			t.Fatalf("getting gauge for fingerprint %q: %v", fp, err)
		}
		m := &dto.Metric{}
		if err := g.Write(m); err != nil {
			t.Fatalf("reading gauge for fingerprint %q: %v", fp, err)
		}
		return m.GetGauge().GetValue()
	}
	if got := gaugeFor(fpA); got != 0 {
		t.Errorf("vhost A's series should read 0 (unhealthy), got %v", got)
	}
	if got := gaugeFor(fpB); got != 1 {
		t.Errorf("vhost B's series should read 1 (healthy), got %v; "+
			"with a shared series this is where A's write would have clobbered B's", got)
	}
}

// TestAdminUpstreamsReportsHealthCheckDiscriminator verifies that the
// /reverse_proxy/upstreams endpoint exposes the health_check fingerprint
// as a public discriminator: two pool entries sharing a dial address must
// be distinguishable, not silently collapsed by consumers indexing on
// address alone.
func TestAdminUpstreamsReportsHealthCheckDiscriminator(t *testing.T) {
	resetDynamicHosts()
	defer drainHostsPool()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	hA, uA, cancelA := newActiveHandler(t, addr, "/vhost-a/health", 1)
	defer cancelA()
	hB, uB, cancelB := newActiveHandler(t, addr, "/vhost-b/health", 1)
	defer cancelB()
	runActiveHealthCheck(t, hA, uA)
	runActiveHealthCheck(t, hB, uB)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/reverse_proxy/upstreams", nil)
	if err := (adminUpstreams{}).handleUpstreams(rec, req); err != nil {
		t.Fatalf("handleUpstreams: %v", err)
	}
	var statuses []upstreamStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &statuses); err != nil {
		t.Fatalf("decoding response: %v", err)
	}

	seen := map[string]int{}
	for _, s := range statuses {
		if s.Address == addr {
			seen[s.HealthCheck]++
		}
	}
	if len(seen) != 2 {
		t.Fatalf("want 2 entries for %s distinguished by health_check, got %d: %v",
			addr, len(seen), seen)
	}
	for fp, n := range seen {
		if fp == "" {
			t.Errorf("entry for %s has empty health_check; address alone cannot identify it", addr)
		}
		if n != 1 {
			t.Errorf("fingerprint %q appears %d times, want 1", fp, n)
		}
	}
}
