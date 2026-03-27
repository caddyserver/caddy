package acmeserver

import (
	"strings"
	"testing"

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
