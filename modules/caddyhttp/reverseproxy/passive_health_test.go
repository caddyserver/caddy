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
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
)

// newPassiveHandler builds a minimal Handler with passive health checks
// configured and a live caddy.Context so the fail-forgetter goroutine can
// be cancelled cleanly. The caller must call cancel() when done.
func newPassiveHandler(t *testing.T, maxFails int, failDuration time.Duration) (*Handler, context.CancelFunc) {
	t.Helper()
	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	h := &Handler{
		ctx: caddyCtx,
		HealthChecks: &HealthChecks{
			Passive: &PassiveHealthChecks{
				MaxFails:     maxFails,
				FailDuration: caddy.Duration(failDuration),
			},
		},
	}
	return h, cancel
}

// provisionedStaticUpstream creates a static upstream, registers it in the
// UsagePool, and returns a cleanup func that removes it from the pool.
func provisionedStaticUpstream(t *testing.T, h *Handler, addr string) (*Upstream, func()) {
	t.Helper()
	u := &Upstream{Dial: addr}
	h.provisionUpstream(u, false)
	return u, func() { _, _ = hosts.Delete(addr) }
}

// provisionedDynamicUpstream creates a dynamic upstream, registers it in
// dynamicHosts, and returns a cleanup func that removes it.
func provisionedDynamicUpstream(t *testing.T, h *Handler, addr string) (*Upstream, func()) {
	t.Helper()
	u := &Upstream{Dial: addr}
	h.provisionUpstream(u, true)
	return u, func() {
		dynamicHostsMu.Lock()
		delete(dynamicHosts, addr)
		dynamicHostsMu.Unlock()
	}
}

// --- countFailure behaviour ---

// TestCountFailureNoopWhenNoHealthChecks verifies that countFailure is a no-op
// when HealthChecks is nil.
func TestCountFailureNoopWhenNoHealthChecks(t *testing.T) {
	resetDynamicHosts()
	h := &Handler{}
	u := &Upstream{Dial: "10.1.0.1:80", Host: new(Host)}

	h.countFailure(u)

	if u.Host.Fails() != 0 {
		t.Errorf("expected 0 fails with no HealthChecks config, got %d", u.Host.Fails())
	}
}

// TestCountFailureNoopWhenZeroDuration verifies that countFailure is a no-op
// when FailDuration is 0 (the zero value disables passive checks).
func TestCountFailureNoopWhenZeroDuration(t *testing.T) {
	resetDynamicHosts()
	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	h := &Handler{
		ctx: caddyCtx,
		HealthChecks: &HealthChecks{
			Passive: &PassiveHealthChecks{MaxFails: 1, FailDuration: 0},
		},
	}
	u := &Upstream{Dial: "10.1.0.2:80", Host: new(Host)}

	h.countFailure(u)

	if u.Host.Fails() != 0 {
		t.Errorf("expected 0 fails with zero FailDuration, got %d", u.Host.Fails())
	}
}

// TestCountFailureIncrementsCount verifies that countFailure increments the
// fail count on the upstream's Host.
func TestCountFailureIncrementsCount(t *testing.T) {
	resetDynamicHosts()
	h, cancel := newPassiveHandler(t, 2, time.Minute)
	defer cancel()
	u := &Upstream{Dial: "10.1.0.3:80", Host: new(Host)}

	h.countFailure(u)

	if u.Host.Fails() != 1 {
		t.Errorf("expected 1 fail after countFailure, got %d", u.Host.Fails())
	}
}

// TestCountFailureDecrementsAfterDuration verifies that the fail count is
// decremented back after FailDuration elapses.
func TestCountFailureDecrementsAfterDuration(t *testing.T) {
	resetDynamicHosts()
	const failDuration = 50 * time.Millisecond
	h, cancel := newPassiveHandler(t, 2, failDuration)
	defer cancel()
	u := &Upstream{Dial: "10.1.0.4:80", Host: new(Host)}

	h.countFailure(u)
	if u.Host.Fails() != 1 {
		t.Fatalf("expected 1 fail immediately after countFailure, got %d", u.Host.Fails())
	}

	// Wait long enough for the forgetter goroutine to fire.
	time.Sleep(3 * failDuration)

	if u.Host.Fails() != 0 {
		t.Errorf("expected fail count to return to 0 after FailDuration, got %d", u.Host.Fails())
	}
}

// TestCountFailureCancelledContextForgets verifies that cancelling the handler
// context (simulating a config unload) also triggers the forgetter to run,
// decrementing the fail count.
func TestCountFailureCancelledContextForgets(t *testing.T) {
	resetDynamicHosts()
	h, cancel := newPassiveHandler(t, 2, time.Hour) // very long duration
	u := &Upstream{Dial: "10.1.0.5:80", Host: new(Host)}

	h.countFailure(u)
	if u.Host.Fails() != 1 {
		t.Fatalf("expected 1 fail immediately after countFailure, got %d", u.Host.Fails())
	}

	// Cancelling the context should cause the forgetter goroutine to exit and
	// decrement the count.
	cancel()
	time.Sleep(50 * time.Millisecond)

	if u.Host.Fails() != 0 {
		t.Errorf("expected fail count to be decremented after context cancel, got %d", u.Host.Fails())
	}
}

// --- static upstream passive health check ---

// TestStaticUpstreamHealthyWithNoFailures verifies that a static upstream with
// no recorded failures is considered healthy.
func TestStaticUpstreamHealthyWithNoFailures(t *testing.T) {
	resetDynamicHosts()
	h, cancel := newPassiveHandler(t, 2, time.Minute)
	defer cancel()

	u, cleanup := provisionedStaticUpstream(t, h, "10.2.0.1:80")
	defer cleanup()

	if !u.Healthy() {
		t.Error("upstream with no failures should be healthy")
	}
}

// TestStaticUpstreamUnhealthyAtMaxFails verifies that a static upstream is
// marked unhealthy once its fail count reaches MaxFails.
func TestStaticUpstreamUnhealthyAtMaxFails(t *testing.T) {
	resetDynamicHosts()
	h, cancel := newPassiveHandler(t, 2, time.Minute)
	defer cancel()

	u, cleanup := provisionedStaticUpstream(t, h, "10.2.0.2:80")
	defer cleanup()

	h.countFailure(u)
	if !u.Healthy() {
		t.Error("upstream should still be healthy after 1 of 2 allowed failures")
	}

	h.countFailure(u)
	if u.Healthy() {
		t.Error("upstream should be unhealthy after reaching MaxFails=2")
	}
}

// TestStaticUpstreamRecoversAfterFailDuration verifies that a static upstream
// returns to healthy once its failures expire.
func TestStaticUpstreamRecoversAfterFailDuration(t *testing.T) {
	resetDynamicHosts()
	const failDuration = 50 * time.Millisecond
	h, cancel := newPassiveHandler(t, 1, failDuration)
	defer cancel()

	u, cleanup := provisionedStaticUpstream(t, h, "10.2.0.3:80")
	defer cleanup()

	h.countFailure(u)
	if u.Healthy() {
		t.Fatal("upstream should be unhealthy immediately after MaxFails failure")
	}

	time.Sleep(3 * failDuration)

	if !u.Healthy() {
		t.Errorf("upstream should recover to healthy after FailDuration, Fails=%d", u.Host.Fails())
	}
}

// TestStaticUpstreamHealthPersistedAcrossReprovisioning verifies that static
// upstreams share a Host via the UsagePool, so a second call to provisionUpstream
// for the same address (as happens on config reload) sees the accumulated state.
func TestStaticUpstreamHealthPersistedAcrossReprovisioning(t *testing.T) {
	resetDynamicHosts()
	h, cancel := newPassiveHandler(t, 2, time.Minute)
	defer cancel()

	u1, cleanup1 := provisionedStaticUpstream(t, h, "10.2.0.4:80")
	defer cleanup1()

	h.countFailure(u1)
	h.countFailure(u1)

	// Simulate a second handler instance referencing the same upstream
	// (e.g. after a config reload that keeps the same backend address).
	u2, cleanup2 := provisionedStaticUpstream(t, h, "10.2.0.4:80")
	defer cleanup2()

	if u1.Host != u2.Host {
		t.Fatal("expected both Upstream structs to share the same *Host via UsagePool")
	}
	if u2.Healthy() {
		t.Error("re-provisioned upstream should still see the prior fail count and be unhealthy")
	}
}

// --- dynamic upstream passive health check ---

// TestDynamicUpstreamHealthyWithNoFailures verifies that a freshly provisioned
// dynamic upstream is healthy.
func TestDynamicUpstreamHealthyWithNoFailures(t *testing.T) {
	resetDynamicHosts()
	h, cancel := newPassiveHandler(t, 2, time.Minute)
	defer cancel()

	u, cleanup := provisionedDynamicUpstream(t, h, "10.3.0.1:80")
	defer cleanup()

	if !u.Healthy() {
		t.Error("dynamic upstream with no failures should be healthy")
	}
}

// TestDynamicUpstreamUnhealthyAtMaxFails verifies that a dynamic upstream is
// marked unhealthy once its fail count reaches MaxFails.
func TestDynamicUpstreamUnhealthyAtMaxFails(t *testing.T) {
	resetDynamicHosts()
	h, cancel := newPassiveHandler(t, 2, time.Minute)
	defer cancel()

	u, cleanup := provisionedDynamicUpstream(t, h, "10.3.0.2:80")
	defer cleanup()

	h.countFailure(u)
	if !u.Healthy() {
		t.Error("dynamic upstream should still be healthy after 1 of 2 allowed failures")
	}

	h.countFailure(u)
	if u.Healthy() {
		t.Error("dynamic upstream should be unhealthy after reaching MaxFails=2")
	}
}

// TestDynamicUpstreamFailCountPersistedBetweenRequests is the core regression
// test: it simulates two sequential (non-concurrent) requests to the same
// dynamic upstream. Before the fix, the UsagePool entry would be deleted
// between requests, wiping the fail count. Now it should survive.
func TestDynamicUpstreamFailCountPersistedBetweenRequests(t *testing.T) {
	resetDynamicHosts()
	h, cancel := newPassiveHandler(t, 2, time.Minute)
	defer cancel()

	// --- first request ---
	u1 := &Upstream{Dial: "10.3.0.3:80"}
	h.provisionUpstream(u1, true)
	h.countFailure(u1)

	if u1.Host.Fails() != 1 {
		t.Fatalf("expected 1 fail after first request, got %d", u1.Host.Fails())
	}

	// Simulate end of first request: no delete from any pool (key difference
	// vs. the old behaviour where hosts.Delete was deferred).

	// --- second request: brand-new *Upstream struct, same dial address ---
	u2 := &Upstream{Dial: "10.3.0.3:80"}
	h.provisionUpstream(u2, true)

	if u1.Host != u2.Host {
		t.Fatal("expected both requests to share the same *Host pointer from dynamicHosts")
	}
	if u2.Host.Fails() != 1 {
		t.Errorf("expected fail count to persist across requests, got %d", u2.Host.Fails())
	}

	// A second failure now tips it over MaxFails=2.
	h.countFailure(u2)
	if u2.Healthy() {
		t.Error("upstream should be unhealthy after accumulated failures across requests")
	}

	// Cleanup.
	dynamicHostsMu.Lock()
	delete(dynamicHosts, "10.3.0.3:80")
	dynamicHostsMu.Unlock()
}

// TestDynamicUpstreamRecoveryAfterFailDuration verifies that a dynamic
// upstream's fail count expires and it returns to healthy.
func TestDynamicUpstreamRecoveryAfterFailDuration(t *testing.T) {
	resetDynamicHosts()
	const failDuration = 50 * time.Millisecond
	h, cancel := newPassiveHandler(t, 1, failDuration)
	defer cancel()

	u, cleanup := provisionedDynamicUpstream(t, h, "10.3.0.4:80")
	defer cleanup()

	h.countFailure(u)
	if u.Healthy() {
		t.Fatal("upstream should be unhealthy immediately after MaxFails failure")
	}

	time.Sleep(3 * failDuration)

	// Re-provision (as a new request would) to get fresh *Upstream with policy set.
	u2 := &Upstream{Dial: "10.3.0.4:80"}
	h.provisionUpstream(u2, true)

	if !u2.Healthy() {
		t.Errorf("dynamic upstream should recover to healthy after FailDuration, Fails=%d", u2.Host.Fails())
	}
}

// TestDynamicUpstreamMaxRequestsFromUnhealthyRequestCount verifies that
// UnhealthyRequestCount is copied into MaxRequests so Full() works correctly.
func TestDynamicUpstreamMaxRequestsFromUnhealthyRequestCount(t *testing.T) {
	resetDynamicHosts()
	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	h := &Handler{
		ctx: caddyCtx,
		HealthChecks: &HealthChecks{
			Passive: &PassiveHealthChecks{
				UnhealthyRequestCount: 3,
			},
		},
	}

	u, cleanup := provisionedDynamicUpstream(t, h, "10.3.0.5:80")
	defer cleanup()

	if u.MaxRequests != 3 {
		t.Errorf("expected MaxRequests=3 from UnhealthyRequestCount, got %d", u.MaxRequests)
	}

	// Should not be full with fewer requests than the limit.
	_ = u.Host.countRequest(2)
	if u.Full() {
		t.Error("upstream should not be full with 2 of 3 allowed requests")
	}

	_ = u.Host.countRequest(1)
	if !u.Full() {
		t.Error("upstream should be full at UnhealthyRequestCount concurrent requests")
	}
}
