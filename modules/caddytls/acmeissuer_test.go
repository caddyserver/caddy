package caddytls

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/acmez/v3/acme"
	"testing"
)

func TestLetsEncryptProfileDefault(t *testing.T) {
	if got := letsEncryptProfile("", ""); got != letsEncryptShortlivedProfile {
		t.Fatalf("default Let's Encrypt CA: got %q, want %q", got, letsEncryptShortlivedProfile)
	}
	if got := letsEncryptProfile(letsEncryptProductionDirectory, ""); got != letsEncryptShortlivedProfile {
		t.Fatalf("production directory: got %q, want %q", got, letsEncryptShortlivedProfile)
	}
	if got := letsEncryptProfile(letsEncryptStagingDirectory, ""); got != letsEncryptShortlivedProfile {
		t.Fatalf("staging directory: got %q, want %q", got, letsEncryptShortlivedProfile)
	}
	if got := letsEncryptProfile("", "classic"); got != "classic" {
		t.Fatalf("long-lived opt-out: got %q, want classic", got)
	}
	if got := letsEncryptProfile("https://acme.example.com/directory", ""); got != "" {
		t.Fatalf("other CA: got %q, want empty", got)
	}
}

func TestACMEIssuerExpandPlaceholders(t *testing.T) {
	t.Setenv("CADDY_TEST_CA_URL", "https://acme.example.com/directory")
	t.Setenv("CADDY_TEST_TEST_CA_URL", "https://acme2.example.com/directory")
	t.Setenv("CADDY_TEST_EAB_KEY_ID", "example-key-id")
	t.Setenv("CADDY_TEST_EAB_MAC_KEY", "example-mac-key")

	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	defer cancel()

	iss := &ACMEIssuer{
		CA:     "{env.CADDY_TEST_CA_URL}",
		TestCA: "{env.CADDY_TEST_TEST_CA_URL}",
		ExternalAccount: &acme.EAB{
			KeyID:  "{env.CADDY_TEST_EAB_KEY_ID}",
			MACKey: "{env.CADDY_TEST_EAB_MAC_KEY}",
		},
	}

	if err := iss.Provision(caddyCtx); err != nil {
		t.Fatalf("Provision() returned unexpected error: %v", err)
	}

	if want := "https://acme.example.com/directory"; iss.CA != want {
		t.Errorf("CA: got %q, want %q", iss.CA, want)
	}
	if want := "https://acme2.example.com/directory"; iss.TestCA != want {
		t.Errorf("TestCA: got %q, want %q", iss.TestCA, want)
	}
	if want := "example-key-id"; iss.ExternalAccount.KeyID != want {
		t.Errorf("ExternalAccount.KeyID: got %q, want %q", iss.ExternalAccount.KeyID, want)
	}
	if want := "example-mac-key"; iss.ExternalAccount.MACKey != want {
		t.Errorf("ExternalAccount.MACKey: got %q, want %q", iss.ExternalAccount.MACKey, want)
	}
}
