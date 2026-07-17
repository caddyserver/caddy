package caddyhttp

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
)

func TestValidateAdminAddressOverlap(t *testing.T) {
	for _, tc := range []struct {
		name           string
		adminAddr      string
		httpListen     string
		adminDisabled  bool
		wantOverlapErr bool
	}{
		{
			name:           "rejects overlapping listener",
			adminAddr:      "localhost:2019",
			httpListen:     "localhost:2019",
			wantOverlapErr: true,
		},
		{
			name:           "rejects identical ephemeral listener",
			adminAddr:      "127.0.0.1:0",
			httpListen:     "127.0.0.1:0",
			wantOverlapErr: true,
		},
		{
			name:       "allows distinct configured listeners",
			adminAddr:  "localhost:2019",
			httpListen: ":2019",
		},
		{
			name:           "allows listener when admin is disabled",
			adminDisabled:  true,
			httpListen:     "localhost:2019",
			wantOverlapErr: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := caddy.Validate(&caddy.Config{
				Admin: &caddy.AdminConfig{Listen: tc.adminAddr, Disabled: tc.adminDisabled},
				AppsRaw: map[string]json.RawMessage{
					"http": httpListenConfig(t, tc.httpListen),
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

func TestRunOverlapDoesNotReplaceAdminServer(t *testing.T) {
	oldPort, newPort := freeTCPPorts(t)
	oldAddr := fmt.Sprintf("127.0.0.1:%d", oldPort)
	newAddr := fmt.Sprintf("127.0.0.1:%d", newPort)

	if err := caddy.Run(&caddy.Config{Admin: &caddy.AdminConfig{Disabled: true}}); err != nil {
		t.Fatalf("disabling initial admin server: %v", err)
	}

	assertOverlapRunRejected(t, newAddr)
	assertNotListening(t, newAddr)

	if err := caddy.Run(&caddy.Config{Admin: &caddy.AdminConfig{Listen: oldAddr}}); err != nil {
		t.Fatalf("starting initial admin server: %v", err)
	}
	t.Cleanup(func() {
		if err := caddy.Run(&caddy.Config{Admin: &caddy.AdminConfig{Disabled: true}}); err != nil {
			t.Errorf("stopping admin server: %v", err)
		}
	})

	assertOverlapRunRejected(t, newAddr)

	assertAdminAvailable(t, oldAddr)
	assertNotListening(t, newAddr)

	busy := busyTCPListenerExcept(t, newAddr)
	defer busy.Close()
	busyAddr := busy.Addr().String()
	err := caddy.Run(&caddy.Config{
		Admin: &caddy.AdminConfig{Listen: newAddr},
		AppsRaw: map[string]json.RawMessage{
			"http": httpListenConfig(t, busyAddr),
		},
	})
	if err == nil || !strings.Contains(err.Error(), "bind") {
		t.Fatalf("expected listener bind error, got: %v", err)
	}
	assertAdminAvailable(t, oldAddr)
	assertNotListening(t, newAddr)
}

func busyTCPListenerExcept(t *testing.T, excludedAddr string) net.Listener {
	t.Helper()
	for {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		if ln.Addr().String() != excludedAddr {
			return ln
		}
		ln.Close()
	}
}

func assertOverlapRunRejected(t *testing.T, addr string) {
	t.Helper()
	err := caddy.Run(&caddy.Config{
		Admin: &caddy.AdminConfig{Listen: addr},
		AppsRaw: map[string]json.RawMessage{
			"http": httpListenConfig(t, addr),
		},
	})
	if err == nil || !strings.Contains(err.Error(), "overlaps with admin API address") {
		t.Fatalf("expected overlap error, got: %v", err)
	}
}

func assertNotListening(t *testing.T, addr string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
	if err == nil {
		conn.Close()
		t.Fatalf("rejected admin server is listening on %s", addr)
	}
}

func assertAdminAvailable(t *testing.T, addr string) {
	t.Helper()
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + addr + "/config/")
	if err != nil {
		t.Fatalf("previous admin server is not available: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("previous admin server returned %s", resp.Status)
	}
}

func freeTCPPorts(t *testing.T) (uint, uint) {
	t.Helper()
	ln1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln1.Close()
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln2.Close()
	return uint(ln1.Addr().(*net.TCPAddr).Port), uint(ln2.Addr().(*net.TCPAddr).Port)
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
