package acmeserver

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
	bolterrors "go.etcd.io/bbolt/errors"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestHandler_warnIfPolicyAllowsAll(t *testing.T) {
	tests := []struct {
		name              string
		policy            *Policy
		wantWarns         int
		wantAllowWildcard bool
	}{
		{
			name:              "warns when policy is nil",
			policy:            nil,
			wantWarns:         1,
			wantAllowWildcard: false,
		},
		{
			name:              "warns when allow/deny rules are empty",
			policy:            &Policy{},
			wantWarns:         1,
			wantAllowWildcard: false,
		},
		{
			name: "warns when only allow_wildcard_names is true",
			policy: &Policy{
				AllowWildcardNames: true,
			},
			wantWarns:         1,
			wantAllowWildcard: true,
		},
		{
			name: "does not warn when allow rules are configured",
			policy: &Policy{
				Allow: &RuleSet{
					Domains: []string{"example.com"},
				},
			},
			wantWarns:         0,
			wantAllowWildcard: false,
		},
		{
			name: "does not warn when deny rules are configured",
			policy: &Policy{
				Deny: &RuleSet{
					Domains: []string{"bad.example.com"},
				},
			},
			wantWarns:         0,
			wantAllowWildcard: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core, logs := observer.New(zap.WarnLevel)
			ash := &Handler{
				CA:     "local",
				Policy: tt.policy,
				logger: zap.New(core),
			}

			ash.warnIfPolicyAllowsAll()
			if logs.Len() != tt.wantWarns {
				t.Fatalf("expected %d warning logs, got %d", tt.wantWarns, logs.Len())
			}

			if tt.wantWarns == 0 {
				return
			}

			entry := logs.All()[0]
			if entry.Level != zap.WarnLevel {
				t.Fatalf("expected warn level, got %v", entry.Level)
			}
			if !strings.Contains(entry.Message, "policy has no allow/deny rules") {
				t.Fatalf("unexpected log message: %q", entry.Message)
			}
			ctx := entry.ContextMap()
			if ctx["ca"] != "local" {
				t.Fatalf("expected ca=local, got %v", ctx["ca"])
			}
			if ctx["allow_wildcard_names"] != tt.wantAllowWildcard {
				t.Fatalf("expected allow_wildcard_names=%v, got %v", tt.wantAllowWildcard, ctx["allow_wildcard_names"])
			}
		})
	}
}

func TestHandler_openDatabaseLocked(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping: bbolt waits 5s for the lock")
	}

	dataDir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dataDir)

	ash := Handler{CA: "locked-db-test", logger: zap.NewNop()}
	key := ash.getDatabaseKey()

	dbFolder := filepath.Join(dataDir, "caddy", "acme_server", key)
	if err := os.MkdirAll(dbFolder, 0o755); err != nil {
		t.Fatalf("making database folder: %v", err)
	}
	dbPath := filepath.Join(dbFolder, "db")

	// hold the lock like a running Caddy instance would
	locked, err := bolt.Open(dbPath, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer locked.Close()

	_, err = ash.openDatabase()
	if err == nil {
		t.Fatal("expected an error opening a locked database, got none")
	}
	if !errors.Is(err, bolterrors.ErrTimeout) {
		t.Errorf("expected error to wrap bolterrors.ErrTimeout, got: %v", err)
	}
	if !strings.Contains(err.Error(), "already locked") {
		t.Errorf("expected error to explain the lock, got: %v", err)
	}
	if _, err := databasePool.Delete(key); err != nil {
		t.Errorf("cleaning up database pool: %v", err)
	}
}
