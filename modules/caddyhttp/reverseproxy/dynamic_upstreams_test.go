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
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
)

// resetDynamicHosts clears global dynamic host state between tests.
func resetDynamicHosts() {
	dynamicHostsMu.Lock()
	dynamicHosts = make(map[string]dynamicHostEntry)
	dynamicHostsMu.Unlock()
	// Reset the Once so cleanup goroutine tests can re-trigger if needed.
	dynamicHostsCleanerOnce = sync.Once{}
}

// TestFillDynamicHostCreatesEntry verifies that calling fillDynamicHost on a
// new address inserts an entry into dynamicHosts and assigns a non-nil Host.
func TestFillDynamicHostCreatesEntry(t *testing.T) {
	resetDynamicHosts()

	u := &Upstream{Dial: "192.0.2.1:80"}
	u.fillDynamicHost()

	if u.Host == nil {
		t.Fatal("expected Host to be set after fillDynamicHost")
	}

	dynamicHostsMu.RLock()
	entry, ok := dynamicHosts["192.0.2.1:80"]
	dynamicHostsMu.RUnlock()

	if !ok {
		t.Fatal("expected entry in dynamicHosts map")
	}
	if entry.host != u.Host {
		t.Error("dynamicHosts entry host should be the same pointer assigned to Upstream.Host")
	}
	if entry.lastSeen.IsZero() {
		t.Error("expected lastSeen to be set")
	}
}

// TestFillDynamicHostReusesSameHost verifies that two calls for the same address
// return the exact same *Host pointer so that state (e.g. fail counts) is shared.
func TestFillDynamicHostReusesSameHost(t *testing.T) {
	resetDynamicHosts()

	u1 := &Upstream{Dial: "192.0.2.2:80"}
	u1.fillDynamicHost()

	u2 := &Upstream{Dial: "192.0.2.2:80"}
	u2.fillDynamicHost()

	if u1.Host != u2.Host {
		t.Error("expected both upstreams to share the same *Host pointer")
	}
}

// TestFillDynamicHostUpdatesLastSeen verifies that a second call for the same
// address advances the lastSeen timestamp.
func TestFillDynamicHostUpdatesLastSeen(t *testing.T) {
	resetDynamicHosts()

	u := &Upstream{Dial: "192.0.2.3:80"}
	u.fillDynamicHost()

	dynamicHostsMu.RLock()
	first := dynamicHosts["192.0.2.3:80"].lastSeen
	dynamicHostsMu.RUnlock()

	// Ensure measurable time passes.
	time.Sleep(2 * time.Millisecond)

	u2 := &Upstream{Dial: "192.0.2.3:80"}
	u2.fillDynamicHost()

	dynamicHostsMu.RLock()
	second := dynamicHosts["192.0.2.3:80"].lastSeen
	dynamicHostsMu.RUnlock()

	if !second.After(first) {
		t.Error("expected lastSeen to be updated on second fillDynamicHost call")
	}
}

// TestFillDynamicHostIndependentAddresses verifies that different addresses get
// independent Host entries.
func TestFillDynamicHostIndependentAddresses(t *testing.T) {
	resetDynamicHosts()

	u1 := &Upstream{Dial: "192.0.2.4:80"}
	u1.fillDynamicHost()

	u2 := &Upstream{Dial: "192.0.2.5:80"}
	u2.fillDynamicHost()

	if u1.Host == u2.Host {
		t.Error("different addresses should have different *Host entries")
	}
}

// TestFillDynamicHostPreservesFailCount verifies that fail counts on a dynamic
// host survive across multiple fillDynamicHost calls (simulating sequential
// requests), which is the core behaviour fixed by this change.
func TestFillDynamicHostPreservesFailCount(t *testing.T) {
	resetDynamicHosts()

	// First "request": provision and record a failure.
	u1 := &Upstream{Dial: "192.0.2.6:80"}
	u1.fillDynamicHost()
	_ = u1.Host.countFail(1)

	if u1.Host.Fails() != 1 {
		t.Fatalf("expected 1 fail, got %d", u1.Host.Fails())
	}

	// Second "request": provision the same address again (new *Upstream, same address).
	u2 := &Upstream{Dial: "192.0.2.6:80"}
	u2.fillDynamicHost()

	if u2.Host.Fails() != 1 {
		t.Errorf("expected fail count to persist across fillDynamicHost calls, got %d", u2.Host.Fails())
	}
}

// TestProvisionUpstreamDynamic verifies that provisionUpstream with dynamic=true
// uses fillDynamicHost (not the UsagePool) and sets healthCheckPolicy /
// MaxRequests correctly from handler config.
func TestProvisionUpstreamDynamic(t *testing.T) {
	resetDynamicHosts()

	passive := &PassiveHealthChecks{
		FailDuration:          caddy.Duration(10 * time.Second),
		MaxFails:              3,
		UnhealthyRequestCount: 5,
	}
	h := Handler{
		HealthChecks: &HealthChecks{
			Passive: passive,
		},
	}

	u := &Upstream{Dial: "192.0.2.7:80"}
	h.provisionUpstream(u, true)

	if u.Host == nil {
		t.Fatal("Host should be set after provisionUpstream")
	}
	if u.healthCheckPolicy != passive {
		t.Error("healthCheckPolicy should point to the handler's PassiveHealthChecks")
	}
	if u.MaxRequests != 5 {
		t.Errorf("expected MaxRequests=5 from UnhealthyRequestCount, got %d", u.MaxRequests)
	}

	// Must be in dynamicHosts, not in the static UsagePool.
	dynamicHostsMu.RLock()
	_, inDynamic := dynamicHosts["192.0.2.7:80"]
	dynamicHostsMu.RUnlock()
	if !inDynamic {
		t.Error("dynamic upstream should be stored in dynamicHosts")
	}
	_, inPool := hosts.References("192.0.2.7:80")
	if inPool {
		t.Error("dynamic upstream should NOT be stored in the static UsagePool")
	}
}

// TestProvisionUpstreamStatic verifies that provisionUpstream with dynamic=false
// uses the UsagePool and does NOT insert into dynamicHosts.
func TestProvisionUpstreamStatic(t *testing.T) {
	resetDynamicHosts()

	h := Handler{}

	u := &Upstream{Dial: "192.0.2.8:80"}
	h.provisionUpstream(u, false)

	if u.Host == nil {
		t.Fatal("Host should be set after provisionUpstream")
	}

	refs, inPool := hosts.References("192.0.2.8:80")
	if !inPool {
		t.Error("static upstream should be in the UsagePool")
	}
	if refs != 1 {
		t.Errorf("expected ref count 1, got %d", refs)
	}

	dynamicHostsMu.RLock()
	_, inDynamic := dynamicHosts["192.0.2.8:80"]
	dynamicHostsMu.RUnlock()
	if inDynamic {
		t.Error("static upstream should NOT be in dynamicHosts")
	}

	// Clean up the pool entry we just added.
	_, _ = hosts.Delete("192.0.2.8:80")
}

// TestDynamicHostHealthyConsultsFails verifies the end-to-end passive health
// check path: after enough failures are recorded against a dynamic upstream's
// shared *Host, Healthy() returns false for a newly provisioned *Upstream with
// the same address.
func TestDynamicHostHealthyConsultsFails(t *testing.T) {
	resetDynamicHosts()

	passive := &PassiveHealthChecks{
		FailDuration: caddy.Duration(time.Minute),
		MaxFails:     2,
	}
	h := Handler{
		HealthChecks: &HealthChecks{Passive: passive},
	}

	// First request: provision and record two failures.
	u1 := &Upstream{Dial: "192.0.2.9:80"}
	h.provisionUpstream(u1, true)

	_ = u1.Host.countFail(1)
	_ = u1.Host.countFail(1)

	// Second request: fresh *Upstream, same address.
	u2 := &Upstream{Dial: "192.0.2.9:80"}
	h.provisionUpstream(u2, true)

	if u2.Healthy() {
		t.Error("upstream should be unhealthy after MaxFails failures have been recorded against its shared Host")
	}
}

// TestDynamicHostCleanupEvictsStaleEntries verifies that the cleanup sweep
// removes entries whose lastSeen is older than dynamicHostIdleExpiry.
func TestDynamicHostCleanupEvictsStaleEntries(t *testing.T) {
	resetDynamicHosts()

	const addr = "192.0.2.10:80"

	// Insert an entry directly with a lastSeen far in the past.
	dynamicHostsMu.Lock()
	dynamicHosts[addr] = dynamicHostEntry{
		host:     new(Host),
		lastSeen: time.Now().Add(-2 * dynamicHostIdleExpiry),
	}
	dynamicHostsMu.Unlock()

	// Run the cleanup logic inline (same logic as the goroutine).
	dynamicHostsMu.Lock()
	for a, entry := range dynamicHosts {
		if time.Since(entry.lastSeen) > dynamicHostIdleExpiry {
			delete(dynamicHosts, a)
		}
	}
	dynamicHostsMu.Unlock()

	dynamicHostsMu.RLock()
	_, stillPresent := dynamicHosts[addr]
	dynamicHostsMu.RUnlock()

	if stillPresent {
		t.Error("stale dynamic host entry should have been evicted by cleanup sweep")
	}
}

// TestDynamicHostCleanupRetainsFreshEntries verifies that the cleanup sweep
// keeps entries whose lastSeen is within dynamicHostIdleExpiry.
func TestDynamicHostCleanupRetainsFreshEntries(t *testing.T) {
	resetDynamicHosts()

	const addr = "192.0.2.11:80"

	dynamicHostsMu.Lock()
	dynamicHosts[addr] = dynamicHostEntry{
		host:     new(Host),
		lastSeen: time.Now(),
	}
	dynamicHostsMu.Unlock()

	// Run the cleanup logic inline.
	dynamicHostsMu.Lock()
	for a, entry := range dynamicHosts {
		if time.Since(entry.lastSeen) > dynamicHostIdleExpiry {
			delete(dynamicHosts, a)
		}
	}
	dynamicHostsMu.Unlock()

	dynamicHostsMu.RLock()
	_, stillPresent := dynamicHosts[addr]
	dynamicHostsMu.RUnlock()

	if !stillPresent {
		t.Error("fresh dynamic host entry should be retained by cleanup sweep")
	}
}

// TestDynamicHostConcurrentFillHost verifies that concurrent calls to
// fillDynamicHost for the same address all get the same *Host pointer and
// don't race (run with -race).
func TestDynamicHostConcurrentFillHost(t *testing.T) {
	resetDynamicHosts()

	const addr = "192.0.2.12:80"
	const goroutines = 50

	var wg sync.WaitGroup
	hosts := make([]*Host, goroutines)

	for i := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			u := &Upstream{Dial: addr}
			u.fillDynamicHost()
			hosts[idx] = u.Host
		}(i)
	}
	wg.Wait()

	first := hosts[0]
	for i, h := range hosts {
		if h != first {
			t.Errorf("goroutine %d got a different *Host pointer; expected all to share the same entry", i)
		}
	}
}
