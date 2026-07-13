package caddyhttp

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

func TestAppAdminAddressOverlap(t *testing.T) {
	for _, tc := range []struct {
		name           string
		adminAddr      string
		httpListen     string
		wantOverlapErr bool
	}{
		{
			name:           "rejects overlapping listener",
			adminAddr:      "localhost:%d",
			httpListen:     ":%d",
			wantOverlapErr: true,
		},
		{
			name:           "allows non-overlapping loopback addresses",
			adminAddr:      "127.0.0.1:%d",
			httpListen:     "127.0.0.2:%d",
			wantOverlapErr: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_ = caddy.Stop()
			t.Cleanup(func() { _ = caddy.Stop() })

			port := freeTCPPort(t)
			err := caddy.Run(&caddy.Config{
				Admin: &caddy.AdminConfig{Listen: fmt.Sprintf(tc.adminAddr, port)},
				AppsRaw: map[string]json.RawMessage{
					"http": httpListenConfig(t, fmt.Sprintf(tc.httpListen, port)),
				},
			})
			if tc.wantOverlapErr {
				if err == nil {
					t.Fatal("expected error")
				}
				if !strings.Contains(err.Error(), "overlaps with admin API address") {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}
		})
	}
}

func freeTCPPort(t *testing.T) uint {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return uint(ln.Addr().(*net.TCPAddr).Port)
}

func httpListenConfig(t *testing.T, addrs ...string) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"servers": map[string]any{
			"srv0": map[string]any{"listen": addrs},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
