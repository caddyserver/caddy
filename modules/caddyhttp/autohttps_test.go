package caddyhttp

import (
	"testing"

	"github.com/caddyserver/caddy/v2"
)

func TestRecordAutoHTTPSRedirectAddressPrefersHTTPSPort(t *testing.T) {
	app := &App{HTTPSPort: 443}
	redirDomains := make(map[string][]caddy.NetworkAddress)

	app.recordAutoHTTPSRedirectAddress(redirDomains, "example.com", caddy.NetworkAddress{Network: "tcp", StartPort: 2345, EndPort: 2345})
	app.recordAutoHTTPSRedirectAddress(redirDomains, "example.com", caddy.NetworkAddress{Network: "tcp", StartPort: 443, EndPort: 443})
	app.recordAutoHTTPSRedirectAddress(redirDomains, "example.com", caddy.NetworkAddress{Network: "tcp", StartPort: 8443, EndPort: 8443})

	got := redirDomains["example.com"]
	if len(got) != 1 {
		t.Fatalf("expected 1 redirect address, got %d: %#v", len(got), got)
	}
	if got[0].StartPort != 443 {
		t.Fatalf("expected redirect to prefer HTTPS port 443, got %#v", got[0])
	}
}

func TestRecordAutoHTTPSRedirectAddressKeepsAllBindAddressesOnWinningPort(t *testing.T) {
	app := &App{HTTPSPort: 443}
	redirDomains := make(map[string][]caddy.NetworkAddress)

	app.recordAutoHTTPSRedirectAddress(redirDomains, "example.com", caddy.NetworkAddress{Network: "tcp", Host: "10.0.0.189", StartPort: 8443, EndPort: 8443})
	app.recordAutoHTTPSRedirectAddress(redirDomains, "example.com", caddy.NetworkAddress{Network: "tcp", Host: "10.0.0.189", StartPort: 443, EndPort: 443})
	app.recordAutoHTTPSRedirectAddress(redirDomains, "example.com", caddy.NetworkAddress{Network: "tcp", Host: "2603:c024:8002:9500:9eb:e5d3:3975:d056", StartPort: 443, EndPort: 443})

	got := redirDomains["example.com"]
	if len(got) != 2 {
		t.Fatalf("expected 2 redirect addresses for both bind addresses on the winning port, got %d: %#v", len(got), got)
	}
	if got[0].StartPort != 443 || got[1].StartPort != 443 {
		t.Fatalf("expected both redirect addresses to stay on HTTPS port 443, got %#v", got)
	}
	if got[0].Host != "10.0.0.189" || got[1].Host != "2603:c024:8002:9500:9eb:e5d3:3975:d056" {
		t.Fatalf("expected both bind addresses to be preserved, got %#v", got)
	}
}
