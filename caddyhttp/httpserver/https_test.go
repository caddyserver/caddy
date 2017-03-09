package httpserver

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mholt/caddy/caddytls"
)

func TestRedirPlaintextHost(t *testing.T) {
	cfg := redirPlaintextHost(&SiteConfig{
		Addr: Address{
			Host: "foohost",
			Port: "1234",
		},
		ListenHost: "93.184.216.34",
		TLS:        new(caddytls.Config),
	})

	// Check host and port
	if actual, expected := cfg.Addr.Host, "foohost"; actual != expected {
		t.Errorf("Expected redir config to have host %s but got %s", expected, actual)
	}
	if actual, expected := cfg.ListenHost, "93.184.216.34"; actual != expected {
		t.Errorf("Expected redir config to have bindhost %s but got %s", expected, actual)
	}
	if actual, expected := cfg.Addr.Port, "80"; actual != expected {
		t.Errorf("Expected redir config to have port '%s' but got '%s'", expected, actual)
	}

	// Make sure redirect handler is set up properly
	if cfg.middleware == nil || len(cfg.middleware) != 1 {
		t.Fatalf("Redir config middleware not set up properly; got: %#v", cfg.middleware)
	}

	handler := cfg.middleware[0](nil)

	// Check redirect for correctness
	rec := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "http://foohost/bar?q=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	status, err := handler.ServeHTTP(rec, req)
	if status != 0 {
		t.Errorf("Expected status return to be 0, but was %d", status)
	}
	if err != nil {
		t.Errorf("Expected returned error to be nil, but was %v", err)
	}
	if rec.Code != http.StatusMovedPermanently {
		t.Errorf("Expected status %d but got %d", http.StatusMovedPermanently, rec.Code)
	}
	if got, want := rec.Header().Get("Location"), "https://foohost:1234/bar?q=1"; got != want {
		t.Errorf("Expected Location: '%s' but got '%s'", want, got)
	}

	// browsers can infer a default port from scheme, so make sure the port
	// doesn't get added in explicitly for default ports like 443 for https.
	cfg = redirPlaintextHost(&SiteConfig{Addr: Address{Host: "foohost", Port: "443"}, TLS: new(caddytls.Config)})
	handler = cfg.middleware[0](nil)

	rec = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "http://foohost/bar?q=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	status, err = handler.ServeHTTP(rec, req)
	if status != 0 {
		t.Errorf("Expected status return to be 0, but was %d", status)
	}
	if err != nil {
		t.Errorf("Expected returned error to be nil, but was %v", err)
	}
	if rec.Code != http.StatusMovedPermanently {
		t.Errorf("Expected status %d but got %d", http.StatusMovedPermanently, rec.Code)
	}
	if got, want := rec.Header().Get("Location"), "https://foohost/bar?q=1"; got != want {
		t.Errorf("Expected Location: '%s' but got '%s'", want, got)
	}
}

func TestHostHasOtherPort(t *testing.T) {
	configs := []*SiteConfig{
		{Addr: Address{Host: "example.com", Port: "80"}},
		{Addr: Address{Host: "sub1.example.com", Port: "80"}},
		{Addr: Address{Host: "sub1.example.com", Port: "443"}},
	}

	if hostHasOtherPort(configs, 0, "80") {
		t.Errorf(`Expected hostHasOtherPort(configs, 0, "80") to be false, but got true`)
	}
	if hostHasOtherPort(configs, 0, "443") {
		t.Errorf(`Expected hostHasOtherPort(configs, 0, "443") to be false, but got true`)
	}
	if !hostHasOtherPort(configs, 1, "443") {
		t.Errorf(`Expected hostHasOtherPort(configs, 1, "443") to be true, but got false`)
	}
}

func TestMakePlaintextRedirects(t *testing.T) {
	configs := []*SiteConfig{
		// Happy path = standard redirect from 80 to 443
		{Addr: Address{Host: "example.com"}, TLS: &caddytls.Config{Managed: true}},

		// Host on port 80 already defined; don't change it (no redirect)
		{Addr: Address{Host: "sub1.example.com", Port: "80", Scheme: "http"}, TLS: new(caddytls.Config)},
		{Addr: Address{Host: "sub1.example.com"}, TLS: &caddytls.Config{Managed: true}},

		// Redirect from port 80 to port 5000 in this case
		{Addr: Address{Host: "sub2.example.com", Port: "5000"}, TLS: &caddytls.Config{Managed: true}},

		// Can redirect from 80 to either 443 or 5001, but choose 443
		{Addr: Address{Host: "sub3.example.com", Port: "443"}, TLS: &caddytls.Config{Managed: true}},
		{Addr: Address{Host: "sub3.example.com", Port: "5001", Scheme: "https"}, TLS: &caddytls.Config{Managed: true}},
	}

	result := makePlaintextRedirects(configs)
	expectedRedirCount := 3

	if len(result) != len(configs)+expectedRedirCount {
		t.Errorf("Expected %d redirect(s) to be added, but got %d",
			expectedRedirCount, len(result)-len(configs))
	}
}

func TestEnableAutoHTTPS(t *testing.T) {
	configs := []*SiteConfig{
		{Addr: Address{Host: "example.com"}, TLS: &caddytls.Config{Managed: true}},
		{}, // not managed - no changes!
	}

	enableAutoHTTPS(configs, false)

	if !configs[0].TLS.Enabled {
		t.Errorf("Expected config 0 to have TLS.Enabled == true, but it was false")
	}
	if configs[0].Addr.Scheme != "https" {
		t.Errorf("Expected config 0 to have Addr.Scheme == \"https\", but it was \"%s\"",
			configs[0].Addr.Scheme)
	}
	if configs[1].TLS != nil && configs[1].TLS.Enabled {
		t.Errorf("Expected config 1 to have TLS.Enabled == false, but it was true")
	}
}

func TestMarkQualifiedForAutoHTTPS(t *testing.T) {
	// TODO: caddytls.TestQualifiesForManagedTLS and this test share nearly the same config list...
	configs := []*SiteConfig{
		{Addr: Address{Host: ""}, TLS: new(caddytls.Config)},
		{Addr: Address{Host: "localhost"}, TLS: new(caddytls.Config)},
		{Addr: Address{Host: "123.44.3.21"}, TLS: new(caddytls.Config)},
		{Addr: Address{Host: "example.com"}, TLS: new(caddytls.Config)},
		{Addr: Address{Host: "example.com"}, TLS: &caddytls.Config{Manual: true}},
		{Addr: Address{Host: "example.com"}, TLS: &caddytls.Config{ACMEEmail: "off"}},
		{Addr: Address{Host: "example.com"}, TLS: &caddytls.Config{ACMEEmail: "foo@bar.com"}},
		{Addr: Address{Host: "example.com", Scheme: "http"}, TLS: new(caddytls.Config)},
		{Addr: Address{Host: "example.com", Port: "80"}, TLS: new(caddytls.Config)},
		{Addr: Address{Host: "example.com", Port: "1234"}, TLS: new(caddytls.Config)},
		{Addr: Address{Host: "example.com", Scheme: "https"}, TLS: new(caddytls.Config)},
		{Addr: Address{Host: "example.com", Port: "80", Scheme: "https"}, TLS: new(caddytls.Config)},
	}
	expectedManagedCount := 4

	markQualifiedForAutoHTTPS(configs)

	count := 0
	for _, cfg := range configs {
		if cfg.TLS.Managed {
			count++
		}
	}

	if count != expectedManagedCount {
		t.Errorf("Expected %d managed configs, but got %d", expectedManagedCount, count)
	}
}
