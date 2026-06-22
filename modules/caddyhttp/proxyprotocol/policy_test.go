package proxyprotocol

import (
	"testing"
)

func TestParsePolicy(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantPolicy Policy
		wantErr    bool
	}{
		{name: "USE", input: "USE", wantPolicy: PolicyUSE},
		{name: "IGNORE", input: "IGNORE", wantPolicy: PolicyIGNORE},
		{name: "REJECT", input: "REJECT", wantPolicy: PolicyREJECT},
		{name: "REQUIRE", input: "REQUIRE", wantPolicy: PolicyREQUIRE},
		{name: "SKIP", input: "SKIP", wantPolicy: PolicySKIP},
		{name: "lowercase use", input: "use", wantPolicy: PolicyUSE},
		{name: "mixed case Ignore", input: "Ignore", wantPolicy: PolicyIGNORE},
		{name: "mixed case rEqUiRe", input: "rEqUiRe", wantPolicy: PolicyREQUIRE},
		{name: "empty string", input: "", wantErr: true},
		{name: "invalid policy", input: "INVALID", wantErr: true},
		{name: "numeric", input: "0", wantErr: true},
		{name: "whitespace", input: " USE ", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePolicy(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parsePolicy(%q) should return error", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("parsePolicy(%q) unexpected error: %v", tt.input, err)
			}
			if got != tt.wantPolicy {
				t.Errorf("parsePolicy(%q) = %d, want %d", tt.input, got, tt.wantPolicy)
			}
		})
	}
}

func TestPolicyMarshalText(t *testing.T) {
	tests := []struct {
		name   string
		policy Policy
		want   string
	}{
		{name: "USE", policy: PolicyUSE, want: "USE"},
		{name: "IGNORE", policy: PolicyIGNORE, want: "IGNORE"},
		{name: "REJECT", policy: PolicyREJECT, want: "REJECT"},
		{name: "REQUIRE", policy: PolicyREQUIRE, want: "REQUIRE"},
		{name: "SKIP", policy: PolicySKIP, want: "SKIP"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.policy.MarshalText()
			if err != nil {
				t.Fatalf("MarshalText() error: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("MarshalText() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPolicyUnmarshalText(t *testing.T) {
	tests := []struct {
		name       string
		text       string
		wantPolicy Policy
		wantErr    bool
	}{
		{name: "USE", text: "USE", wantPolicy: PolicyUSE},
		{name: "lowercase skip", text: "skip", wantPolicy: PolicySKIP},
		{name: "invalid", text: "INVALID", wantErr: true},
		{name: "empty", text: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var p Policy
			err := p.UnmarshalText([]byte(tt.text))
			if tt.wantErr {
				if err == nil {
					t.Errorf("UnmarshalText(%q) should return error", tt.text)
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalText(%q) unexpected error: %v", tt.text, err)
			}
			if p != tt.wantPolicy {
				t.Errorf("UnmarshalText(%q) resulted in %d, want %d", tt.text, p, tt.wantPolicy)
			}
		})
	}
}

func TestPolicyMarshalUnmarshalRoundTrip(t *testing.T) {
	policies := []Policy{PolicyIGNORE, PolicyUSE, PolicyREJECT, PolicyREQUIRE, PolicySKIP}

	for _, p := range policies {
		text, err := p.MarshalText()
		if err != nil {
			t.Fatalf("MarshalText() for policy %d error: %v", p, err)
		}

		var roundTripped Policy
		err = roundTripped.UnmarshalText(text)
		if err != nil {
			t.Fatalf("UnmarshalText(%q) error: %v", text, err)
		}

		if roundTripped != p {
			t.Errorf("round-trip failed: started with %d, got %d after marshal/unmarshal", p, roundTripped)
		}
	}
}

func TestPolicyConstants(t *testing.T) {
	// Verify iota ordering matches expected values
	if PolicyIGNORE != 0 {
		t.Errorf("PolicyIGNORE = %d, want 0", PolicyIGNORE)
	}
	if PolicyUSE != 1 {
		t.Errorf("PolicyUSE = %d, want 1", PolicyUSE)
	}
	if PolicyREJECT != 2 {
		t.Errorf("PolicyREJECT = %d, want 2", PolicyREJECT)
	}
	if PolicyREQUIRE != 3 {
		t.Errorf("PolicyREQUIRE = %d, want 3", PolicyREQUIRE)
	}
	if PolicySKIP != 4 {
		t.Errorf("PolicySKIP = %d, want 4", PolicySKIP)
	}
}

func TestPolicyMapCompleteness(t *testing.T) {
	policies := []Policy{PolicyIGNORE, PolicyUSE, PolicyREJECT, PolicyREQUIRE, PolicySKIP}

	for _, p := range policies {
		// Every policy should be in policyMap
		if _, ok := policyMap[p]; !ok {
			t.Errorf("policyMap missing entry for policy %d", p)
		}
		// Every policy should map to a go-proxyproto policy
		if _, ok := policyToGoProxyPolicy[p]; !ok {
			t.Errorf("policyToGoProxyPolicy missing entry for policy %d", p)
		}
	}

	// Every entry in policyMapRev should have a corresponding policyMap entry
	for name, p := range policyMapRev {
		if policyMap[p] != name {
			t.Errorf("policyMap[%d] = %q, but policyMapRev[%q] = %d (inconsistent)", p, policyMap[p], name, p)
		}
	}
}

func TestPolicyMarshalUnknown(t *testing.T) {
	// An unknown policy value should marshal to empty string (not in map)
	p := Policy(99)
	text, err := p.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText() error: %v", err)
	}
	if string(text) != "" {
		t.Errorf("MarshalText() for unknown policy = %q, want empty string", text)
	}
}
