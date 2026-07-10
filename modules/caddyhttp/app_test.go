package caddyhttp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

func TestAppRejectsAdminPort(t *testing.T) {
	t.Cleanup(func() { _ = caddy.Stop() })

	err := caddy.Run(&caddy.Config{
		AppsRaw: map[string]json.RawMessage{
			"http": []byte(`{"servers":{"srv0":{"listen":[":2019"]}}}`),
		},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "overlaps with admin API address") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAppAllowsNonOverlappingAdminAddress(t *testing.T) {
	t.Cleanup(func() { _ = caddy.Stop() })

	err := caddy.Run(&caddy.Config{
		Admin: &caddy.AdminConfig{Listen: "127.0.0.1:2019"},
		AppsRaw: map[string]json.RawMessage{
			"http": []byte(`{"servers":{"srv0":{"listen":["127.0.0.2:2019"]}}}`),
		},
	})
	if err != nil && strings.Contains(err.Error(), "overlaps with admin API address") {
		t.Fatalf("unexpected admin overlap error: %v", err)
	}
}
