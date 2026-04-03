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

// TestConsecutiveCounterResetOnPass verifies that a health check pass
// resets the consecutive failure counter to zero. Without this, non-
// consecutive failures could accumulate and incorrectly trip the threshold.
func TestConsecutiveCounterResetOnPass(t *testing.T) {
	host := new(Host)

	// Simulate: fail, fail, then pass
	host.countHealthFail(1)
	host.countHealthFail(1)
	if host.activeHealthFails() != 2 {
		t.Fatalf("expected 2 fails, got %d", host.activeHealthFails())
	}

	// A pass should reset the fail counter
	host.countHealthPass(1)
	if host.activeHealthFails() != 0 {
		t.Errorf("expected fail counter to reset to 0 after a pass, got %d", host.activeHealthFails())
	}
	if host.activeHealthPasses() != 1 {
		t.Errorf("expected 1 pass, got %d", host.activeHealthPasses())
	}
}

// TestConsecutiveCounterResetOnFail verifies that a health check failure
// resets the consecutive pass counter to zero.
func TestConsecutiveCounterResetOnFail(t *testing.T) {
	host := new(Host)

	// Simulate: pass, pass, then fail
	host.countHealthPass(1)
	host.countHealthPass(1)
	if host.activeHealthPasses() != 2 {
		t.Fatalf("expected 2 passes, got %d", host.activeHealthPasses())
	}

	// A fail should reset the pass counter
	host.countHealthFail(1)
	if host.activeHealthPasses() != 0 {
		t.Errorf("expected pass counter to reset to 0 after a fail, got %d", host.activeHealthPasses())
	}
	if host.activeHealthFails() != 1 {
		t.Errorf("expected 1 fail, got %d", host.activeHealthFails())
	}
}

// TestNonConsecutiveFailuresDoNotTripThreshold is a regression test:
// interleaved pass/fail results must NOT accumulate toward the threshold.
// Before the fix, fail-pass-fail-pass-fail would reach Fails=3 even
// though there were zero consecutive failures.
func TestNonConsecutiveFailuresDoNotTripThreshold(t *testing.T) {
	host := new(Host)

	// Interleave: fail, pass, fail, pass, fail
	for i := 0; i < 3; i++ {
		host.countHealthFail(1)
		if i < 2 {
			host.countHealthPass(1)
		}
	}

	// With correct consecutive tracking, we should have only 1 consecutive fail
	if host.activeHealthFails() != 1 {
		t.Errorf("expected 1 consecutive fail, got %d", host.activeHealthFails())
	}
}

// TestConsecutiveFailuresDoTripThreshold verifies that truly consecutive
// failures correctly accumulate and trip the threshold.
func TestConsecutiveFailuresDoTripThreshold(t *testing.T) {
	host := new(Host)

	const failThreshold = 3

	host.countHealthFail(1)
	host.countHealthFail(1)
	host.countHealthFail(1)

	if host.activeHealthFails() != 3 {
		t.Errorf("expected 3 consecutive fails, got %d", host.activeHealthFails())
	}
	if host.activeHealthFails() < failThreshold {
		t.Error("3 consecutive failures should trip threshold of 3")
	}
	// Pass counter should be 0 (reset by the first fail)
	if host.activeHealthPasses() != 0 {
		t.Errorf("expected 0 passes after consecutive fails, got %d", host.activeHealthPasses())
	}
}

// TestInitiallyUnhealthy verifies that when InitiallyUnhealthy is true
// and there are no prior health check passes, the upstream starts unhealthy.
func TestInitiallyUnhealthy(t *testing.T) {
	upstream := &Upstream{
		Dial: "10.4.0.1:80",
		Host: new(Host),
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
	host := new(Host)
	host.countHealthPass(1) // simulate a prior health check pass

	upstream := &Upstream{
		Dial: "10.4.0.2:80",
		Host: host,
	}

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
		Dial: "10.4.0.3:80",
		Host: new(Host),
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
	host := new(Host)
	host.countHealthFail(1) // simulate a prior failure

	upstream := &Upstream{
		Dial: "10.4.0.4:80",
		Host: host,
	}

	fails := 1
	upstream.setHealthy(upstream.activeHealthFails() < fails)

	if upstream.healthy() {
		t.Error("upstream should be unhealthy when it has prior failures >= threshold")
	}
}
