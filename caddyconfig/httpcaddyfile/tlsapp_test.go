package httpcaddyfile

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

func TestAutomationPolicyIsSubset(t *testing.T) {
	for i, test := range []struct {
		a, b   []string
		expect bool
	}{
		{
			a:      []string{"example.com"},
			b:      []string{},
			expect: true,
		},
		{
			a:      []string{},
			b:      []string{"example.com"},
			expect: false,
		},
		{
			a:      []string{"foo.example.com"},
			b:      []string{"*.example.com"},
			expect: true,
		},
		{
			a:      []string{"foo.example.com"},
			b:      []string{"foo.example.com"},
			expect: true,
		},
		{
			a:      []string{"foo.example.com"},
			b:      []string{"example.com"},
			expect: false,
		},
		{
			a:      []string{"example.com", "foo.example.com"},
			b:      []string{"*.com", "*.*.com"},
			expect: true,
		},
		{
			a:      []string{"example.com", "foo.example.com"},
			b:      []string{"*.com"},
			expect: false,
		},
	} {
		apA := &caddytls.AutomationPolicy{SubjectsRaw: test.a}
		apB := &caddytls.AutomationPolicy{SubjectsRaw: test.b}
		if actual := automationPolicyIsSubset(apA, apB); actual != test.expect {
			t.Errorf("Test %d: Expected %t but got %t (A: %v  B: %v)", i, test.expect, actual, test.a, test.b)
		}
	}
}

func TestAutomationPoliciesAllowSameHostOnDifferentPorts(t *testing.T) {
	input := `https://example.com:5000 localhost:5000 {
	respond "one"
}

https://example.net localhost:8080 {
	respond "two"
}
`

	adapter := caddyfile.Adapter{ServerType: ServerType{}}
	_, _, err := adapter.Adapt([]byte(input), nil)
	if err != nil {
		t.Fatalf("adapting Caddyfile: %v", err)
	}
}

func TestConsolidateAutomationPoliciesSpecificity(t *testing.T) {
	t.Run("overlapping wildcard and exact subject sets in both insertion orders", func(t *testing.T) {
		pWildcard := &caddytls.AutomationPolicy{
			SubjectsRaw: []string{"*.example.com", "other.com", "third.com"},
			KeyType:     "rsa2048",
		}
		pSpecific := &caddytls.AutomationPolicy{
			SubjectsRaw: []string{"foo.example.com", "e.com"},
			KeyType:     "ed25519",
		}

		res1, err := consolidateAutomationPolicies([]*caddytls.AutomationPolicy{pWildcard, pSpecific})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(res1) != 2 || res1[0] != pSpecific || res1[1] != pWildcard {
			t.Fatalf("expected [pSpecific, pWildcard], got %v", res1)
		}

		res2, err := consolidateAutomationPolicies([]*caddytls.AutomationPolicy{pSpecific, pWildcard})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(res2) != 2 || res2[0] != pSpecific || res2[1] != pWildcard {
			t.Fatalf("expected [pSpecific, pWildcard], got %v", res2)
		}
	})

	t.Run("disjoint unequal-size sets preserve insertion order", func(t *testing.T) {
		p1 := &caddytls.AutomationPolicy{
			SubjectsRaw: []string{"alpha.example.com", "beta.example.com", "gamma.example.com"},
			KeyType:     "ed25519",
		}
		p2 := &caddytls.AutomationPolicy{
			SubjectsRaw: []string{"delta.example.org"},
			KeyType:     "rsa2048",
		}

		res1, err := consolidateAutomationPolicies([]*caddytls.AutomationPolicy{p1, p2})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(res1) != 2 || res1[0] != p1 || res1[1] != p2 {
			t.Fatalf("expected [p1, p2], got %v", res1)
		}

		res2, err := consolidateAutomationPolicies([]*caddytls.AutomationPolicy{p2, p1})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(res2) != 2 || res2[0] != p2 || res2[1] != p1 {
			t.Fatalf("expected [p2, p1], got %v", res2)
		}
	})

	t.Run("catch-all policy sorted after specific policies", func(t *testing.T) {
		pCatchAll := &caddytls.AutomationPolicy{SubjectsRaw: nil, KeyType: "p256"}
		pWildcard := &caddytls.AutomationPolicy{SubjectsRaw: []string{"*.example.com"}, KeyType: "rsa2048"}
		pExact := &caddytls.AutomationPolicy{SubjectsRaw: []string{"foo.example.com"}, KeyType: "ed25519"}

		res1, err := consolidateAutomationPolicies([]*caddytls.AutomationPolicy{pCatchAll, pWildcard, pExact})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(res1) != 3 || res1[0] != pExact || res1[1] != pWildcard || res1[2] != pCatchAll {
			t.Fatalf("expected [pExact, pWildcard, pCatchAll], got %v", res1)
		}

		res2, err := consolidateAutomationPolicies([]*caddytls.AutomationPolicy{pExact, pWildcard, pCatchAll})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(res2) != 3 || res2[0] != pExact || res2[1] != pWildcard || res2[2] != pCatchAll {
			t.Fatalf("expected [pExact, pWildcard, pCatchAll], got %v", res2)
		}
	})

	t.Run("bidirectional conflict with different configurations returns error", func(t *testing.T) {
		p1 := &caddytls.AutomationPolicy{SubjectsRaw: []string{"foo.example.com", "*.other.com"}, KeyType: "rsa2048"}
		p2 := &caddytls.AutomationPolicy{SubjectsRaw: []string{"*.example.com", "bar.other.com"}, KeyType: "ed25519"}

		_, err := consolidateAutomationPolicies([]*caddytls.AutomationPolicy{p1, p2})
		if err == nil {
			t.Fatalf("expected error for conflicting policies with different configurations, got nil")
		}
	})

	t.Run("merge-equivalent crossed policies consolidate without error", func(t *testing.T) {
		p1 := &caddytls.AutomationPolicy{SubjectsRaw: []string{"foo.example.com", "*.other.com"}, KeyType: "rsa2048"}
		p2 := &caddytls.AutomationPolicy{SubjectsRaw: []string{"*.example.com", "bar.other.com"}, KeyType: "rsa2048"}

		res, err := consolidateAutomationPolicies([]*caddytls.AutomationPolicy{p1, p2})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(res) != 1 {
			t.Fatalf("expected 1 consolidated policy, got %d", len(res))
		}
		expectedSubjs := []string{"foo.example.com", "*.other.com", "*.example.com", "bar.other.com"}
		for _, exp := range expectedSubjs {
			if !slices.Contains(res[0].SubjectsRaw, exp) {
				t.Errorf("expected subject %s in consolidated policy, got %v", exp, res[0].SubjectsRaw)
			}
		}
	})

	t.Run("merge-equivalent crossed policies that shadow intermediate policy returns error", func(t *testing.T) {
		p1 := &caddytls.AutomationPolicy{SubjectsRaw: []string{"foo.example.com", "*.other.com"}, KeyType: "rsa2048"}
		p2 := &caddytls.AutomationPolicy{SubjectsRaw: []string{"baz.example.com"}, KeyType: "ed25519"}
		p3 := &caddytls.AutomationPolicy{SubjectsRaw: []string{"*.example.com", "bar.other.com"}, KeyType: "rsa2048"}

		_, err := consolidateAutomationPolicies([]*caddytls.AutomationPolicy{p1, p2, p3})
		if err == nil {
			t.Fatalf("expected error when merge would shadow intermediate policy, got nil")
		}
	})
}

func TestConsolidateAutomationPoliciesCaddyfileAdapt(t *testing.T) {
	t.Run("issue 8300 site blocks adapt with specific policy first", func(t *testing.T) {
		input := `*.example.com, other.com, third.com {
	tls internal
}

foo.example.com, e.com {
	tls {
		issuer acme
	}
}
`
		adapter := caddyfile.Adapter{ServerType: ServerType{}}
		cfgJSON, _, err := adapter.Adapt([]byte(input), nil)
		if err != nil {
			t.Fatalf("unexpected error adapting Caddyfile: %v", err)
		}

		var parsedCfg struct {
			Apps struct {
				TLS struct {
					Automation struct {
						Policies []struct {
							Subjects []string `json:"subjects"`
						} `json:"policies"`
					} `json:"automation"`
				} `json:"tls"`
			} `json:"apps"`
		}
		if err := json.Unmarshal(cfgJSON, &parsedCfg); err != nil {
			t.Fatalf("unmarshaling config: %v", err)
		}

		policies := parsedCfg.Apps.TLS.Automation.Policies
		if len(policies) < 2 {
			t.Fatalf("expected at least 2 automation policies, got %d", len(policies))
		}
		if !slices.Contains(policies[0].Subjects, "foo.example.com") {
			t.Errorf("expected policy 0 to contain foo.example.com, got %v", policies[0].Subjects)
		}
		if !slices.Contains(policies[1].Subjects, "*.example.com") {
			t.Errorf("expected policy 1 to contain *.example.com, got %v", policies[1].Subjects)
		}
	})

	t.Run("conflicting crossed site blocks fail adapt", func(t *testing.T) {
		input := `foo.example.com, *.other.com {
	tls {
		key_type rsa2048
	}
}

*.example.com, bar.other.com {
	tls {
		key_type ed25519
	}
}
`
		adapter := caddyfile.Adapter{ServerType: ServerType{}}
		_, _, err := adapter.Adapt([]byte(input), nil)
		if err == nil {
			t.Fatalf("expected error adapting conflicting crossed site blocks, got nil")
		}
	})
}

