package caddyauth

import (
	"context"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

// Regression test for https://github.com/caddyserver/caddy/issues/8037:
// duplicate usernames that only collide after {env.*} expansion must be
// rejected at provision time.
func TestProvisionRejectsDuplicateAfterEnvExpansion(t *testing.T) {
	t.Setenv("CADDY_TEST_USER", "carol")

	newCtx := func(t *testing.T) caddy.Context {
		t.Helper()
		ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
		t.Cleanup(cancel)
		return ctx
	}

	t.Run("collision after expansion errors", func(t *testing.T) {
		hba := HTTPBasicAuth{AccountList: []Account{
			{Username: "carol", Password: "cHcx"},
			{Username: "{env.CADDY_TEST_USER}", Password: "cHcy"},
		}}
		err := hba.Provision(newCtx(t))
		if err == nil || !strings.Contains(err.Error(), "username is not unique: carol") {
			t.Fatalf("expected duplicate-username error for expanded 'carol', got: %v", err)
		}
	})

	t.Run("two placeholders expanding to same name error", func(t *testing.T) {
		t.Setenv("CADDY_TEST_USER_B", "carol")
		hba := HTTPBasicAuth{AccountList: []Account{
			{Username: "{env.CADDY_TEST_USER}", Password: "cHcx"},
			{Username: "{env.CADDY_TEST_USER_B}", Password: "cHcy"},
		}}
		err := hba.Provision(newCtx(t))
		if err == nil || !strings.Contains(err.Error(), "username is not unique: carol") {
			t.Fatalf("expected duplicate-username error for expanded 'carol', got: %v", err)
		}
	})

	t.Run("distinct expanded names pass", func(t *testing.T) {
		hba := HTTPBasicAuth{AccountList: []Account{
			{Username: "{env.CADDY_TEST_USER}", Password: "cHcx"},
			{Username: "dave", Password: "cHcy"},
		}}
		if err := hba.Provision(newCtx(t)); err != nil {
			t.Fatalf("expected no error for distinct users, got: %v", err)
		}
	})

	t.Run("literal duplicates still rejected", func(t *testing.T) {
		hba := HTTPBasicAuth{AccountList: []Account{
			{Username: "carol", Password: "cHcx"},
			{Username: "carol", Password: "cHcy"},
		}}
		if err := hba.Provision(newCtx(t)); err == nil {
			t.Fatal("expected duplicate-username error for literal duplicates, got nil")
		}
	})

	t.Run("unset placeholder rejected as required", func(t *testing.T) {
		hba := HTTPBasicAuth{AccountList: []Account{
			{Username: "{env.CADDY_TEST_MISSING_USER}", Password: "cHcx"},
		}}
		err := hba.Provision(newCtx(t))
		if err == nil || !strings.Contains(err.Error(), "username and password are required") {
			t.Fatalf("expected required-field error for unset placeholder, got: %v", err)
		}
	})
}
