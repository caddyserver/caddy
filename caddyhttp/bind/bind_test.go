package bind

import (
	"testing"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func TestSetupBind(t *testing.T) {
	c := caddy.NewTestController("http", `bind 1.2.3.4`)
	err := setupBind(c)
	if err != nil {
		t.Fatalf("Expected no errors, but got: %v", err)
	}

	cfg := httpserver.GetConfig(c)
	if got, want := cfg.ListenHost, "1.2.3.4"; got != want {
		t.Errorf("Expected the config's ListenHost to be %s, was %s", want, got)
	}
	if got, want := cfg.TLS.ListenHost, "1.2.3.4"; got != want {
		t.Errorf("Expected the TLS config's ListenHost to be %s, was %s", want, got)
	}
}
