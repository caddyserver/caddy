package letsencrypt

import (
	"net/http"
	"testing"

	"github.com/mholt/caddy/middleware/redirect"
	"github.com/mholt/caddy/server"
)

func TestRedirPlaintextHost(t *testing.T) {
	cfg := redirPlaintextHost(server.Config{
		Host: "example.com",
		Port: "http",
	})

	// Check host and port
	if actual, expected := cfg.Host, "example.com"; actual != expected {
		t.Errorf("Expected redir config to have host %s but got %s", expected, actual)
	}
	if actual, expected := cfg.Port, "http"; actual != expected {
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
