package httpcaddyfile

import (
	"encoding/json"
	"testing"

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

func TestConsolidateAutomationPoliciesWildcardManager(t *testing.T) {
	httpManager := json.RawMessage(`{"via":"http"}`)

	for i, test := range []struct {
		policies []*caddytls.AutomationPolicy
		expect   int // expected number of policies after consolidation; -1 means nil
	}{
		{
			// empty subdomain policy should be removed when covered by
			// a wildcard policy with get_certificate (#7559)
			policies: []*caddytls.AutomationPolicy{
				{SubjectsRaw: []string{"foo.example.com"}},
				{SubjectsRaw: []string{"*.example.com"}, ManagersRaw: []json.RawMessage{httpManager}},
			},
			expect: 1,
		},
		{
			// empty policy with no wildcard coverage should be kept
			policies: []*caddytls.AutomationPolicy{
				{SubjectsRaw: []string{"example.com"}},
				{SubjectsRaw: []string{"*.other.com"}, ManagersRaw: []json.RawMessage{httpManager}},
			},
			expect: 2,
		},
	} {
		result := consolidateAutomationPolicies(test.policies)
		var got int
		if result == nil {
			got = -1
		} else {
			got = len(result)
		}
		if got != test.expect {
			t.Errorf("Test %d: Expected %d policies but got %d", i, test.expect, got)
		}
	}
}
