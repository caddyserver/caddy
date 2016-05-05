package proxy

import (
	"testing"
	"time"
)

func TestNewHost(t *testing.T) {
	upstream := &staticUpstream{
		FailTimeout: 10 * time.Second,
		MaxConns:    1,
		MaxFails:    1,
	}

	uh, err := upstream.NewHost("example.com")
	if err != nil {
		t.Error("Expected no error")
	}
	if uh.Name != "http://example.com" {
		t.Error("Expected default schema to be added to Name.")
	}
	if uh.FailTimeout != upstream.FailTimeout {
		t.Error("Expected default FailTimeout to be set.")
	}
	if uh.MaxConns != upstream.MaxConns {
		t.Error("Expected default MaxConns to be set.")
	}
	if uh.CheckDown == nil {
		t.Error("Expected default CheckDown to be set.")
	}
	if uh.CheckDown(uh) {
		t.Error("Expected new host not to be down.")
	}
	// mark Unhealthy
	uh.Unhealthy = true
	if !uh.CheckDown(uh) {
		t.Error("Expected unhealthy host to be down.")
	}
	// mark with Fails
	uh.Unhealthy = false
	uh.Fails = 1
	if !uh.CheckDown(uh) {
		t.Error("Expected failed host to be down.")
	}
}

func TestHealthCheck(t *testing.T) {
	upstream := &staticUpstream{
		from:        "",
		Hosts:       testPool(),
		Policy:      &Random{},
		FailTimeout: 10 * time.Second,
		MaxFails:    1,
	}
	upstream.healthCheck()
	if upstream.Hosts[0].Down() {
		t.Error("Expected first host in testpool to not fail healthcheck.")
	}
	if !upstream.Hosts[1].Down() {
		t.Error("Expected second host in testpool to fail healthcheck.")
	}
}

func TestSelect(t *testing.T) {
	upstream := &staticUpstream{
		from:        "",
		Hosts:       testPool()[:3],
		Policy:      &Random{},
		FailTimeout: 10 * time.Second,
		MaxFails:    1,
	}
	upstream.Hosts[0].Unhealthy = true
	upstream.Hosts[1].Unhealthy = true
	upstream.Hosts[2].Unhealthy = true
	if h := upstream.Select(); h != nil {
		t.Error("Expected select to return nil as all host are down")
	}
	upstream.Hosts[2].Unhealthy = false
	if h := upstream.Select(); h == nil {
		t.Error("Expected select to not return nil")
	}
	upstream.Hosts[0].Conns = 1
	upstream.Hosts[0].MaxConns = 1
	upstream.Hosts[1].Conns = 1
	upstream.Hosts[1].MaxConns = 1
	upstream.Hosts[2].Conns = 1
	upstream.Hosts[2].MaxConns = 1
	if h := upstream.Select(); h != nil {
		t.Error("Expected select to return nil as all hosts are full")
	}
	upstream.Hosts[2].Conns = 0
	if h := upstream.Select(); h == nil {
		t.Error("Expected select to not return nil")
	}
}

func TestRegisterPolicy(t *testing.T) {
	name := "custom"
	customPolicy := &customPolicy{}
	RegisterPolicy(name, func() Policy { return customPolicy })
	if _, ok := supportedPolicies[name]; !ok {
		t.Error("Expected supportedPolicies to have a custom policy.")
	}

}

func TestAllowedPaths(t *testing.T) {
	upstream := &staticUpstream{
		from:            "/proxy",
		IgnoredSubPaths: []string{"/download", "/static"},
	}
	tests := []struct {
		url      string
		expected bool
	}{
		{"/proxy", true},
		{"/proxy/dl", true},
		{"/proxy/download", false},
		{"/proxy/download/static", false},
		{"/proxy/static", false},
		{"/proxy/static/download", false},
		{"/proxy/something/download", true},
		{"/proxy/something/static", true},
		{"/proxy//static", false},
		{"/proxy//static//download", false},
		{"/proxy//download", false},
	}

	for i, test := range tests {
		allowed := upstream.AllowedPath(test.url)
		if test.expected != allowed {
			t.Errorf("Test %d: expected %v found %v", i+1, test.expected, allowed)
		}
	}
}
