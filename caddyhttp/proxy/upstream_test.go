package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mholt/caddy/caddyfile"
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
	uh.Unhealthy = 1
	if !uh.CheckDown(uh) {
		t.Error("Expected unhealthy host to be down.")
	}
	// mark with Fails
	uh.Unhealthy = 0
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
	r, _ := http.NewRequest("GET", "/", nil)
	upstream.Hosts[0].Unhealthy = 1
	upstream.Hosts[1].Unhealthy = 1
	upstream.Hosts[2].Unhealthy = 1
	if h := upstream.Select(r); h != nil {
		t.Error("Expected select to return nil as all host are down")
	}
	upstream.Hosts[2].Unhealthy = 0
	if h := upstream.Select(r); h == nil {
		t.Error("Expected select to not return nil")
	}
	upstream.Hosts[0].Conns = 1
	upstream.Hosts[0].MaxConns = 1
	upstream.Hosts[1].Conns = 1
	upstream.Hosts[1].MaxConns = 1
	upstream.Hosts[2].Conns = 1
	upstream.Hosts[2].MaxConns = 1
	if h := upstream.Select(r); h != nil {
		t.Error("Expected select to return nil as all hosts are full")
	}
	upstream.Hosts[2].Conns = 0
	if h := upstream.Select(r); h == nil {
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

func TestParseBlockHealthCheck(t *testing.T) {
	tests := []struct {
		config   string
		interval string
		timeout  string
	}{
		// Test #1: Both options set correct time
		{"health_check /health\n health_check_interval 10s\n health_check_timeout 20s", "10s", "20s"},

		// Test #2: Health check options flipped around. Making sure health_check doesn't overwrite it
		{"health_check_interval 10s\n health_check_timeout 20s\n health_check /health", "10s", "20s"},

		// Test #3: No health_check options. So default.
		{"health_check /health", "30s", "1m0s"},

		// Test #4: Interval sets it to 15s and timeout defaults
		{"health_check /health\n health_check_interval 15s", "15s", "1m0s"},

		// Test #5: Timeout sets it to 15s and interval defaults
		{"health_check /health\n health_check_timeout 15s", "30s", "15s"},

		// Test #6: Some funky spelling to make sure it still defaults
		{"health_check /health health_check_time 15s", "30s", "1m0s"},
	}

	for i, test := range tests {
		u := staticUpstream{}
		c := caddyfile.NewDispenser("Testfile", strings.NewReader(test.config))
		for c.Next() {
			parseBlock(&c, &u)
		}
		if u.HealthCheck.Interval.String() != test.interval {
			t.Errorf(
				"Test %d: HealthCheck interval not the same from config. Got %v. Expected: %v",
				i+1,
				u.HealthCheck.Interval,
				test.interval,
			)
		}
		if u.HealthCheck.Timeout.String() != test.timeout {
			t.Errorf(
				"Test %d: HealthCheck timeout not the same from config. Got %v. Expected: %v",
				i+1,
				u.HealthCheck.Timeout,
				test.timeout,
			)
		}
	}
}

func TestStop(t *testing.T) {
	config := "proxy / %s {\n health_check /healthcheck \nhealth_check_interval %dms \n}"
	tests := []struct {
		name                    string
		intervalInMilliseconds  int
		numHealthcheckIntervals int
	}{
		{
			"No Healthchecks After Stop - 5ms, 1 intervals",
			5,
			1,
		},
		{
			"No Healthchecks After Stop - 5ms, 2 intervals",
			5,
			2,
		},
		{
			"No Healthchecks After Stop - 5ms, 3 intervals",
			5,
			3,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			// Set up proxy.
			var counter int64
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r.Body.Close()
				atomic.AddInt64(&counter, 1)
			}))

			defer backend.Close()

			upstreams, err := NewStaticUpstreams(caddyfile.NewDispenser("Testfile", strings.NewReader(fmt.Sprintf(config, backend.URL, test.intervalInMilliseconds))), "")
			if err != nil {
				t.Error("Expected no error. Got:", err.Error())
			}

			// Give some time for healthchecks to hit the server.
			time.Sleep(time.Duration(test.intervalInMilliseconds*test.numHealthcheckIntervals) * time.Millisecond)

			for _, upstream := range upstreams {
				if err := upstream.Stop(); err != nil {
					t.Error("Expected no error stopping upstream. Got: ", err.Error())
				}
			}

			counterValueAfterShutdown := atomic.LoadInt64(&counter)

			// Give some time to see if healthchecks are still hitting the server.
			time.Sleep(time.Duration(test.intervalInMilliseconds*test.numHealthcheckIntervals) * time.Millisecond)

			if counterValueAfterShutdown == 0 {
				t.Error("Expected healthchecks to hit test server. Got no healthchecks.")
			}

			counterValueAfterWaiting := atomic.LoadInt64(&counter)
			if counterValueAfterWaiting != counterValueAfterShutdown {
				t.Errorf("Expected no more healthchecks after shutdown. Got: %d healthchecks after shutdown", counterValueAfterWaiting-counterValueAfterShutdown)
			}

		})

	}
}

func TestParseBlock(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	tests := []struct {
		config string
	}{
		// Test #1: transparent preset
		{"proxy / localhost:8080 {\n transparent \n}"},

		// Test #2: transparent preset with another param
		{"proxy / localhost:8080 {\n transparent \nheader_upstream X-Test Tester \n}"},

		// Test #3: transparent preset on multiple sites
		{"proxy / localhost:8080 {\n transparent \n} \nproxy /api localhost:8081 { \ntransparent \n}"},
	}

	for i, test := range tests {
		upstreams, err := NewStaticUpstreams(caddyfile.NewDispenser("Testfile", strings.NewReader(test.config)), "")
		if err != nil {
			t.Errorf("Expected no error. Got: %s", err.Error())
		}
		for _, upstream := range upstreams {
			headers := upstream.Select(r).UpstreamHeaders

			if _, ok := headers["Host"]; !ok {
				t.Errorf("Test %d: Could not find the Host header", i+1)
			}

			if _, ok := headers["X-Real-Ip"]; !ok {
				t.Errorf("Test %d: Could not find the X-Real-Ip header", i+1)
			}

			if _, ok := headers["X-Forwarded-Proto"]; !ok {
				t.Errorf("Test %d: Could not find the X-Forwarded-Proto header", i+1)
			}
		}
	}
}

func TestHealthSetUp(t *testing.T) {
	// tests for insecure skip verify
	tests := []struct {
		config string
		flag   bool
	}{
		// Test #1: without flag
		{"proxy / localhost:8080 {\n health_check / \n}", false},

		// Test #2: with flag
		{"proxy / localhost:8080 {\n health_check / \n insecure_skip_verify \n}", true},
	}

	for i, test := range tests {
		upstreams, err := NewStaticUpstreams(caddyfile.NewDispenser("Testfile", strings.NewReader(test.config)), "")
		if err != nil {
			t.Errorf("Expected no error. Got: %s", err.Error())
		}
		for _, upstream := range upstreams {
			staticUpstream, ok := upstream.(*staticUpstream)
			if !ok {
				t.Errorf("Type mismatch: %#v", upstream)
				continue
			}
			transport, ok := staticUpstream.HealthCheck.Client.Transport.(*http.Transport)
			if !ok {
				t.Errorf("Type mismatch: %#v", staticUpstream.HealthCheck.Client.Transport)
				continue
			}
			if test.flag != transport.TLSClientConfig.InsecureSkipVerify {
				t.Errorf("Test %d: expected transport.TLSClientCnfig.InsecureSkipVerify=%v, got %v", i, test.flag, transport.TLSClientConfig.InsecureSkipVerify)
			}
		}
	}
}

func TestHealthCheckHost(t *testing.T) {
	// tests for upstream host on health checks
	tests := []struct {
		config string
		flag   bool
		host   string
	}{
		// Test #1: without upstream header
		{"proxy / localhost:8080 {\n health_check / \n}", false, "example.com"},

		// Test #2: without upstream header, missing host
		{"proxy / localhost:8080 {\n health_check / \n}", true, ""},

		// Test #3: with upstream header (via transparent preset)
		{"proxy / localhost:8080 {\n health_check / \n transparent \n}", true, "foo.example.com"},

		// Test #4: with upstream header (explicit header)
		{"proxy / localhost:8080 {\n health_check / \n header_upstream Host {host} \n}", true, "example.com"},

		// Test #5: with upstream header, missing host
		{"proxy / localhost:8080 {\n health_check / \n transparent \n}", true, ""},
	}

	for i, test := range tests {
		upstreams, err := NewStaticUpstreams(caddyfile.NewDispenser("Testfile", strings.NewReader(test.config)), test.host)
		if err != nil {
			t.Errorf("Expected no error. Got: %s", err.Error())
		}
		for _, upstream := range upstreams {
			staticUpstream, ok := upstream.(*staticUpstream)
			if !ok {
				t.Errorf("Type mismatch: %#v", upstream)
				continue
			}
			if test.flag != (staticUpstream.HealthCheck.Host == test.host) {
				t.Errorf("Test %d: expected staticUpstream.HealthCheck.Host=%v, got %v", i, test.host, staticUpstream.HealthCheck.Host)
			}
		}
	}
}
