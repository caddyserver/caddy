package letsencrypt

import (
	"net/http"
	"testing"

	"github.com/mholt/caddy/middleware/redirect"
	"github.com/mholt/caddy/server"
)

func TestHostQualifies(t *testing.T) {
	for i, test := range []struct {
		host   string
		expect bool
	}{
		{"localhost", false},
		{"127.0.0.1", false},
		{"127.0.1.5", false},
		{"::1", false},
		{"[::1]", false},
		{"[::]", false},
		{"::", false},
		{"", false},
		{" ", false},
		{"0.0.0.0", false},
		{"192.168.1.3", false},
		{"10.0.2.1", false},
		{"169.112.53.4", false},
		{"foobar.com", true},
		{"sub.foobar.com", true},
	} {
		if HostQualifies(test.host) && !test.expect {
			t.Errorf("Test %d: Expected '%s' to NOT qualify, but it did", i, test.host)
		}
		if !HostQualifies(test.host) && test.expect {
			t.Errorf("Test %d: Expected '%s' to qualify, but it did NOT", i, test.host)
		}
	}
}

func TestRedirPlaintextHost(t *testing.T) {
	cfg := redirPlaintextHost(server.Config{
		Host: "example.com",
		Port: "80",
	})

	// Check host and port
	if actual, expected := cfg.Host, "example.com"; actual != expected {
		t.Errorf("Expected redir config to have host %s but got %s", expected, actual)
	}
	if actual, expected := cfg.Port, "80"; actual != expected {
		t.Errorf("Expected redir config to have port '%s' but got '%s'", expected, actual)
	}

	// Make sure redirect handler is set up properly
	if cfg.Middleware == nil || len(cfg.Middleware["/"]) != 1 {
		t.Fatalf("Redir config middleware not set up properly; got: %#v", cfg.Middleware)
	}

	handler, ok := cfg.Middleware["/"][0](nil).(redirect.Redirect)
	if !ok {
		t.Fatalf("Expected a redirect.Redirect middleware, but got: %#v", handler)
	}
	if len(handler.Rules) != 1 {
		t.Fatalf("Expected one redirect rule, got: %#v", handler.Rules)
	}

	// Check redirect rule for correctness
	if actual, expected := handler.Rules[0].FromScheme, "http"; actual != expected {
		t.Errorf("Expected redirect rule to be from scheme '%s' but is actually from '%s'", expected, actual)
	}
	if actual, expected := handler.Rules[0].FromPath, "/"; actual != expected {
		t.Errorf("Expected redirect rule to be for path '%s' but is actually for '%s'", expected, actual)
	}
	if actual, expected := handler.Rules[0].To, "https://example.com{uri}"; actual != expected {
		t.Errorf("Expected redirect rule to be to URL '%s' but is actually to '%s'", expected, actual)
	}
	if actual, expected := handler.Rules[0].Code, http.StatusMovedPermanently; actual != expected {
		t.Errorf("Expected redirect rule to have code %d but was %d", expected, actual)
	}
}
