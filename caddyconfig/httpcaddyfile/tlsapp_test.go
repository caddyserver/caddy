package httpcaddyfile

import (
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
	t.Run("wildcard before specific sorted by specificity", func(t *testing.T) {
		pWildcard := &caddytls.AutomationPolicy{
			SubjectsRaw: []string{"*.example.com", "other.com", "third.com"},
			KeyType:     "rsa2048",
		}
		pSpecific := &caddytls.AutomationPolicy{
			SubjectsRaw: []string{"foo.example.com", "e.com"},
			KeyType:     "ed25519",
		}

		res, err := consolidateAutomationPolicies([]*caddytls.AutomationPolicy{pWildcard, pSpecific})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(res) != 2 {
			t.Fatalf("expected 2 policies, got %d", len(res))
		}
		if res[0] != pSpecific {
			t.Errorf("expected specific policy at index 0, got %v", res[0].SubjectsRaw)
		}
		if res[1] != pWildcard {
			t.Errorf("expected wildcard policy at index 1, got %v", res[1].SubjectsRaw)
		}
	})

	t.Run("bidirectional conflict returns error", func(t *testing.T) {
		p1 := &caddytls.AutomationPolicy{SubjectsRaw: []string{"foo.example.com", "*.other.com"}}
		p2 := &caddytls.AutomationPolicy{SubjectsRaw: []string{"*.example.com", "bar.other.com"}}

		_, err := consolidateAutomationPolicies([]*caddytls.AutomationPolicy{p1, p2})
		if err == nil {
			t.Fatalf("expected error for conflicting policies, got nil")
		}
	})
}
