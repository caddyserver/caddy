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
	if !strings.Contains(err.Error(), "admin API port") {
		t.Fatalf("unexpected error: %v", err)
	}
}
