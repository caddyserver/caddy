package caddytls

import (
	"testing"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

// TestGetAutomationPolicyForNameIPv6Brackets verifies that getAutomationPolicyForName
// does NOT match a policy registered for "2a12:4944:efe4::" when given the bracketed
// form "[2a12:4944:efe4::]" that Go's HTTP server places in r.Host for IPv6 requests.
func TestGetAutomationPolicyForNameIPv6Brackets(t *testing.T) {
	ipv6Addr := "2a12:4944:efe4::"

	specificPolicy := &AutomationPolicy{
		subjects: []string{ipv6Addr},
	}
	defaultPolicy := &AutomationPolicy{}

	tlsApp := &TLS{
		Automation: &AutomationConfig{
			Policies:                        []*AutomationPolicy{specificPolicy},
			defaultPublicAutomationPolicy:   defaultPolicy,
			defaultInternalAutomationPolicy: defaultPolicy,
		},
	}

	got := tlsApp.getAutomationPolicyForName("[" + ipv6Addr + "]")
	if got == specificPolicy {
		t.Errorf("getAutomationPolicyForName with bracketed IPv6 host should NOT match the specific policy (bug: brackets prevent matching)")
	}

	got = tlsApp.getAutomationPolicyForName(ipv6Addr)
	if got != specificPolicy {
		t.Errorf("getAutomationPolicyForName with un-bracketed IPv6 host should return specific policy, got %v", got)
	}
}

func TestAutomationPolicyMakeCertMagicConfigImplicitTailscaleManagersOnly(t *testing.T) {
	ap := AutomationPolicy{
		Managers: []certmagic.Manager{Tailscale{}},
		subjects: []string{"test-node.example.ts.net"},
	}

	cfg, err := ap.makeCertMagicConfig(&TLS{
		logger: zap.NewNop(),
	}, nil, &certmagic.FileStorage{Path: t.TempDir()})
	if err != nil {
		t.Fatalf("making certmagic config: %v", err)
	}
	if cfg.OnDemand == nil {
		t.Fatal("expected on-demand config to be set")
	}
	if len(cfg.Issuers) != 0 {
		t.Fatalf("expected no issuers for tailscale-managed ts.net policy, got %d", len(cfg.Issuers))
	}
}

func TestAutomationPolicyImplicitTailscaleManagersOnlyCatchAll(t *testing.T) {
	ap := AutomationPolicy{
		Managers: []certmagic.Manager{Tailscale{}},
	}
	if ap.implicitTailscaleManagersOnly() {
		t.Fatal("expected catch-all manager policy to remain outside tailscale-only special case")
	}
}
