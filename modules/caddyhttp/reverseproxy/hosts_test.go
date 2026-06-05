package reverseproxy

import (
	"sync"
	"testing"
)

func TestHostNumRequests(t *testing.T) {
	h := new(Host)
	if got := h.NumRequests(); got != 0 {
		t.Errorf("NumRequests() = %d, want 0", got)
	}
	h.countRequest(1)
	if got := h.NumRequests(); got != 1 {
		t.Errorf("NumRequests() = %d, want 1", got)
	}
	h.countRequest(1)
	if got := h.NumRequests(); got != 2 {
		t.Errorf("NumRequests() = %d, want 2", got)
	}
	h.countRequest(-1)
	if got := h.NumRequests(); got != 1 {
		t.Errorf("NumRequests() = %d, want 1", got)
	}
}

func TestHostFails(t *testing.T) {
	h := new(Host)
	if got := h.Fails(); got != 0 {
		t.Errorf("Fails() = %d, want 0", got)
	}
	h.countFail(1)
	if got := h.Fails(); got != 1 {
		t.Errorf("Fails() = %d, want 1", got)
	}
	h.countFail(1)
	if got := h.Fails(); got != 2 {
		t.Errorf("Fails() = %d, want 2", got)
	}
}

func TestHostCountRequestBelowZero(t *testing.T) {
	h := new(Host)
	err := h.countRequest(-1)
	if err == nil {
		t.Error("countRequest(-1) on zero should return error")
	}
}

func TestHostCountFailBelowZero(t *testing.T) {
	h := new(Host)
	err := h.countFail(-1)
	if err == nil {
		t.Error("countFail(-1) on zero should return error")
	}
}

func TestHostActiveHealthCounters(t *testing.T) {
	h := new(Host)
	if got := h.activeHealthPasses(); got != 0 {
		t.Errorf("activeHealthPasses() = %d, want 0", got)
	}
	if got := h.activeHealthFails(); got != 0 {
		t.Errorf("activeHealthFails() = %d, want 0", got)
	}

	h.countHealthPass(1)
	h.countHealthFail(1)
	if got := h.activeHealthPasses(); got != 1 {
		t.Errorf("activeHealthPasses() = %d, want 1", got)
	}
	if got := h.activeHealthFails(); got != 1 {
		t.Errorf("activeHealthFails() = %d, want 1", got)
	}
}

func TestHostResetHealth(t *testing.T) {
	h := new(Host)
	h.countHealthPass(5)
	h.countHealthFail(3)
	h.resetHealth()
	if got := h.activeHealthPasses(); got != 0 {
		t.Errorf("activeHealthPasses() after reset = %d, want 0", got)
	}
	if got := h.activeHealthFails(); got != 0 {
		t.Errorf("activeHealthFails() after reset = %d, want 0", got)
	}
}

func TestUpstreamString(t *testing.T) {
	u := &Upstream{Dial: "localhost:8080", Host: new(Host)}
	if got := u.String(); got != "localhost:8080" {
		t.Errorf("String() = %q, want 'localhost:8080'", got)
	}
}

func TestUpstreamHealthy(t *testing.T) {
	u := &Upstream{Host: new(Host)}
	if !u.healthy() {
		t.Error("new Upstream should be healthy")
	}
}

func TestUpstreamSetHealthy(t *testing.T) {
	u := &Upstream{Host: new(Host)}

	// Initially healthy; setting to unhealthy should return true (changed)
	changed := u.setHealthy(false)
	if !changed {
		t.Error("setHealthy(false) should return true (value changed)")
	}
	if u.healthy() {
		t.Error("should be unhealthy after setHealthy(false)")
	}

	// Setting to unhealthy again should return false (no change)
	changed = u.setHealthy(false)
	if changed {
		t.Error("setHealthy(false) again should return false (no change)")
	}

	// Setting to healthy should return true (changed)
	changed = u.setHealthy(true)
	if !changed {
		t.Error("setHealthy(true) should return true (value changed)")
	}
	if !u.healthy() {
		t.Error("should be healthy after setHealthy(true)")
	}
}

func TestUpstreamAvailable(t *testing.T) {
	u := &Upstream{Host: new(Host)}
	if !u.Available() {
		t.Error("new Upstream should be available")
	}

	// Mark unhealthy
	u.setHealthy(false)
	if u.Available() {
		t.Error("unhealthy Upstream should not be available")
	}

	// Restore healthy, set max requests
	u.setHealthy(true)
	u.MaxRequests = 1
	u.Host.countRequest(1)
	if u.Available() {
		t.Error("full Upstream should not be available")
	}
}

func TestUpstreamFull(t *testing.T) {
	u := &Upstream{Host: new(Host), MaxRequests: 2}
	if u.Full() {
		t.Error("should not be full with 0 requests")
	}
	u.Host.countRequest(1)
	if u.Full() {
		t.Error("should not be full with 1/2 requests")
	}
	u.Host.countRequest(1)
	if !u.Full() {
		t.Error("should be full with 2/2 requests")
	}
}

func TestUpstreamFullZeroMax(t *testing.T) {
	u := &Upstream{Host: new(Host), MaxRequests: 0}
	u.Host.countRequest(100)
	if u.Full() {
		t.Error("Full() should be false when MaxRequests is 0 (unlimited)")
	}
}

func TestDialInfoString(t *testing.T) {
	tests := []struct {
		name    string
		di      DialInfo
		wantStr string
	}{
		{
			name:    "tcp host:port",
			di:      DialInfo{Network: "tcp", Host: "localhost", Port: "8080"},
			wantStr: "tcp/localhost:8080",
		},
		{
			name:    "empty network",
			di:      DialInfo{Host: "localhost", Port: "443"},
			wantStr: "localhost:443",
		},
		{
			name:    "unix socket",
			di:      DialInfo{Network: "unix", Host: "/var/run/app.sock"},
			wantStr: "unix//var/run/app.sock",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.di.String()
			if got != tt.wantStr {
				t.Errorf("String() = %q, want %q", got, tt.wantStr)
			}
		})
	}
}

func TestHostConcurrentAccess(t *testing.T) {
	h := new(Host)
	var wg sync.WaitGroup
	n := 100

	// Concurrent increments
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.countRequest(1)
		}()
	}
	wg.Wait()

	if got := h.NumRequests(); got != n {
		t.Errorf("NumRequests() after %d concurrent increments = %d", n, got)
	}

	// Concurrent decrements
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.countRequest(-1)
		}()
	}
	wg.Wait()

	if got := h.NumRequests(); got != 0 {
		t.Errorf("NumRequests() after concurrent decrements = %d, want 0", got)
	}
}

func TestHostConcurrentFails(t *testing.T) {
	h := new(Host)
	var wg sync.WaitGroup
	n := 100

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.countFail(1)
		}()
	}
	wg.Wait()

	if got := h.Fails(); got != n {
		t.Errorf("Fails() after %d concurrent increments = %d", n, got)
	}
}
