package httpcaddyfile

import (
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

func TestMergeACMEIssuers(t *testing.T) {
	base := &caddytls.ACMEIssuer{
		Email: "ops@example.com",
		Challenges: &caddytls.ChallengesConfig{
			HTTP: &caddytls.HTTPChallengeConfig{
				AlternatePort: 8080,
			},
			TLSALPN: &caddytls.TLSALPNChallengeConfig{
				Disabled:      true,
				AlternatePort: 8443,
			},
			DNS: &caddytls.DNSChallengeConfig{
				Resolvers:      []string{"1.1.1.1"},
				OverrideDomain: "_acme-challenge.example.net",
			},
		},
		TrustedRootsPEMFiles: []string{"global.pem"},
	}
	overrides := &caddytls.ACMEIssuer{
		CA: "https://deglacme01.company.intern/acme/acme/directory",
		Challenges: &caddytls.ChallengesConfig{
			HTTP: &caddytls.HTTPChallengeConfig{
				Disabled: true,
			},
			DNS: &caddytls.DNSChallengeConfig{
				PropagationTimeout: caddy.Duration(time.Minute),
			},
		},
		TrustedRootsPEMFiles: []string{"site.pem"},
	}

	merged := mergeACMEIssuers(base, overrides)
	if merged.CA != overrides.CA {
		t.Fatalf("expected merged CA %q, got %q", overrides.CA, merged.CA)
	}
	if merged.Email != base.Email {
		t.Fatalf("expected merged email %q, got %q", base.Email, merged.Email)
	}
	if len(merged.TrustedRootsPEMFiles) != 2 || merged.TrustedRootsPEMFiles[0] != "global.pem" || merged.TrustedRootsPEMFiles[1] != "site.pem" {
		t.Fatalf("expected merged roots [global.pem site.pem], got %v", merged.TrustedRootsPEMFiles)
	}
	if merged.Challenges == nil || merged.Challenges.HTTP == nil || !merged.Challenges.HTTP.Disabled || merged.Challenges.HTTP.AlternatePort != 8080 {
		t.Fatalf("expected merged HTTP challenge config to preserve alternate port and apply disable flag, got %#v", merged.Challenges)
	}
	if merged.Challenges.TLSALPN == nil || !merged.Challenges.TLSALPN.Disabled || merged.Challenges.TLSALPN.AlternatePort != 8443 {
		t.Fatalf("expected merged TLS-ALPN challenge config to preserve global settings, got %#v", merged.Challenges)
	}
	if merged.Challenges.DNS == nil || merged.Challenges.DNS.PropagationTimeout != caddy.Duration(time.Minute) || len(merged.Challenges.DNS.Resolvers) != 1 || merged.Challenges.DNS.Resolvers[0] != "1.1.1.1" || merged.Challenges.DNS.OverrideDomain != "_acme-challenge.example.net" {
		t.Fatalf("expected merged DNS challenge config to preserve global values and apply overrides, got %#v", merged.Challenges)
	}

	if base.CA != "" {
		t.Fatalf("expected base issuer to remain unchanged, got CA %q", base.CA)
	}
	if len(base.TrustedRootsPEMFiles) != 1 || base.TrustedRootsPEMFiles[0] != "global.pem" {
		t.Fatalf("expected base roots to remain unchanged, got %v", base.TrustedRootsPEMFiles)
	}
}

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
