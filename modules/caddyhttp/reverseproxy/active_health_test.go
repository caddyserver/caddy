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
	"testing"
)

func newTestUpstream() *Upstream {
	return &Upstream{
		Host:              new(Host),
		activeHealthStats: &ActiveHealthStats{},
	}
}

// TestConsecutiveCounterResetOnPass verifies that a health check pass
// resets the consecutive failure counter to zero. Without this, non-
// consecutive failures could accumulate and incorrectly trip the threshold.
func TestConsecutiveCounterResetOnPass(t *testing.T) {
	upstream := newTestUpstream()

	// Simulate: fail, fail, then pass
	upstream.countHealthFail(1)
	upstream.countHealthFail(1)
	if upstream.activeHealthFails() != 2 {
		t.Fatalf("expected 2 fails, got %d", upstream.activeHealthFails())
	}

	// A pass should reset the fail counter
	upstream.countHealthPass(1)
	if upstream.activeHealthFails() != 0 {
		t.Errorf("expected fail counter to reset to 0 after a pass, got %d", upstream.activeHealthFails())
	}
	if upstream.activeHealthPasses() != 1 {
		t.Errorf("expected 1 pass, got %d", upstream.activeHealthPasses())
	}
}

// TestConsecutiveCounterResetOnFail verifies that a health check failure
// resets the consecutive pass counter to zero.
func TestConsecutiveCounterResetOnFail(t *testing.T) {
	upstream := newTestUpstream()

	// Simulate: pass, pass, then fail
	upstream.countHealthPass(1)
	upstream.countHealthPass(1)
	if upstream.activeHealthPasses() != 2 {
		t.Fatalf("expected 2 passes, got %d", upstream.activeHealthPasses())
	}

	// A fail should reset the pass counter
	upstream.countHealthFail(1)
	if upstream.activeHealthPasses() != 0 {
		t.Errorf("expected pass counter to reset to 0 after a fail, got %d", upstream.activeHealthPasses())
	}
	if upstream.activeHealthFails() != 1 {
		t.Errorf("expected 1 fail, got %d", upstream.activeHealthFails())
	}
}

// TestNonConsecutiveFailuresDoNotTripThreshold is a regression test:
// interleaved pass/fail results must NOT accumulate toward the threshold.
// Before the fix, fail-pass-fail-pass-fail would reach Fails=3 even
// though there were zero consecutive failures.
func TestNonConsecutiveFailuresDoNotTripThreshold(t *testing.T) {
	upstream := newTestUpstream()

	// Interleave: fail, pass, fail, pass, fail
	for i := 0; i < 3; i++ {
		upstream.countHealthFail(1)
		if i < 2 {
			upstream.countHealthPass(1)
		}
	}

	// With correct consecutive tracking, we should have only 1 consecutive fail
	if upstream.activeHealthFails() != 1 {
		t.Errorf("expected 1 consecutive fail, got %d", upstream.activeHealthFails())
	}
}

// TestConsecutiveFailuresDoTripThreshold verifies that truly consecutive
// failures correctly accumulate and trip the threshold.
func TestConsecutiveFailuresDoTripThreshold(t *testing.T) {
	upstream := newTestUpstream()

	const failThreshold = 3

	upstream.countHealthFail(1)
	upstream.countHealthFail(1)
	upstream.countHealthFail(1)

	if upstream.activeHealthFails() != 3 {
		t.Errorf("expected 3 consecutive fails, got %d", upstream.activeHealthFails())
	}
	if upstream.activeHealthFails() < failThreshold {
		t.Error("3 consecutive failures should trip threshold of 3")
	}
	// Pass counter should be 0 (reset by the first fail)
	if upstream.activeHealthPasses() != 0 {
		t.Errorf("expected 0 passes after consecutive fails, got %d", upstream.activeHealthPasses())
	}
}

// TestInitiallyUnhealthy verifies that when InitiallyUnhealthy is true
// and there are no prior health check passes, the upstream starts unhealthy.
func TestInitiallyUnhealthy(t *testing.T) {
	upstream := &Upstream{
		Dial:              "10.4.0.1:80",
		Host:              new(Host),
		activeHealthStats: &ActiveHealthStats{},
	}

	// Simulate what Provision does when InitiallyUnhealthy=true and
	// passes=0 (fresh host, no prior health checks)
	passes := 1 // default Passes threshold
	upstream.setHealthy(upstream.activeHealthPasses() >= passes)

	if upstream.healthy() {
		t.Error("upstream should be unhealthy when InitiallyUnhealthy=true and no passes recorded")
	}
}

// TestInitiallyUnhealthyWithPriorPasses verifies that when InitiallyUnhealthy
// is true but the host already has enough passes (e.g., across a reload),
// it starts healthy.
func TestInitiallyUnhealthyWithPriorPasses(t *testing.T) {
	stats := &ActiveHealthStats{}
	upstream := &Upstream{
		Dial:              "10.4.0.2:80",
		Host:              new(Host),
		activeHealthStats: stats,
	}
	upstream.countHealthPass(1) // simulate a prior health check pass

	passes := 1
	upstream.setHealthy(upstream.activeHealthPasses() >= passes)

	if !upstream.healthy() {
		t.Error("upstream should be healthy when it has enough prior passes, even with InitiallyUnhealthy=true")
	}
}

// TestInitiallyHealthyDefault verifies the default behavior: upstreams
// start healthy unless they have accumulated enough failures.
func TestInitiallyHealthyDefault(t *testing.T) {
	upstream := &Upstream{
		Dial:              "10.4.0.3:80",
		Host:              new(Host),
		activeHealthStats: &ActiveHealthStats{},
	}

	// Default behavior: healthy unless fails >= threshold
	fails := 1
	upstream.setHealthy(upstream.activeHealthFails() < fails)

	if !upstream.healthy() {
		t.Error("upstream should be healthy by default when no failures recorded")
	}
}

// TestInitiallyHealthyDefaultWithPriorFails verifies that an upstream
// with prior failures (e.g., from before a reload) starts unhealthy.
func TestInitiallyHealthyDefaultWithPriorFails(t *testing.T) {
	upstream := &Upstream{
		Dial:              "10.4.0.4:80",
		Host:              new(Host),
		activeHealthStats: &ActiveHealthStats{},
	}
	upstream.countHealthFail(1) // simulate a prior failure

	fails := 1
	upstream.setHealthy(upstream.activeHealthFails() < fails)

	if upstream.healthy() {
		t.Error("upstream should be unhealthy when it has prior failures >= threshold")
	}
}
