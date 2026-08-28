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
