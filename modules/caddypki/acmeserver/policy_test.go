package acmeserver

import (
	"reflect"
	"testing"

	"github.com/smallstep/certificates/authority/policy"
	"github.com/smallstep/certificates/authority/provisioner"
)

func TestPolicyNormalizeAllowRules(t *testing.T) {
	type fields struct {
		Allow              *RuleSet
		Deny               *RuleSet
		AllowWildcardNames bool
	}
	tests := []struct {
		name   string
		fields fields
		want   *policy.X509NameOptions
	}{
		{
			name:   "providing no rules results in 'nil'",
			fields: fields{},
			want:   nil,
		},
		{
			name: "providing 'nil' Allow rules results in 'nil', regardless of Deny rules",
			fields: fields{
				Allow:              nil,
				Deny:               &RuleSet{},
				AllowWildcardNames: true,
			},
			want: nil,
		},
		{
			name: "providing empty Allow rules results in 'nil', regardless of Deny rules",
			fields: fields{
				Allow: &RuleSet{
					Domains:  []string{},
					IPRanges: []string{},
				},
			},
			want: nil,
		},
		{
			name: "rules configured in Allow are returned in X509NameOptions",
			fields: fields{
				Allow: &RuleSet{
					Domains:  []string{"example.com"},
					IPRanges: []string{"127.0.0.1/32"},
				},
			},
			want: &policy.X509NameOptions{
				DNSDomains: []string{"example.com"},
				IPRanges:   []string{"127.0.0.1/32"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Policy{
				Allow:              tt.fields.Allow,
				Deny:               tt.fields.Deny,
				AllowWildcardNames: tt.fields.AllowWildcardNames,
			}
			if got := p.normalizeAllowRules(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Policy.normalizeAllowRules() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPolicy_normalizeDenyRules(t *testing.T) {
	type fields struct {
		Allow              *RuleSet
		Deny               *RuleSet
		AllowWildcardNames bool
	}
	tests := []struct {
		name   string
		fields fields
		want   *policy.X509NameOptions
	}{
		{
			name:   "providing no rules results in 'nil'",
			fields: fields{},
			want:   nil,
		},
		{
			name: "providing 'nil' Deny rules results in 'nil', regardless of Allow rules",
			fields: fields{
				Deny:               nil,
				Allow:              &RuleSet{},
				AllowWildcardNames: true,
			},
			want: nil,
		},
		{
			name: "providing empty Deny rules results in 'nil', regardless of Allow rules",
			fields: fields{
				Deny: &RuleSet{
					Domains:  []string{},
					IPRanges: []string{},
				},
			},
			want: nil,
		},
		{
			name: "rules configured in Deny are returned in X509NameOptions",
			fields: fields{
				Deny: &RuleSet{
					Domains:  []string{"example.com"},
					IPRanges: []string{"127.0.0.1/32"},
				},
			},
			want: &policy.X509NameOptions{
				DNSDomains: []string{"example.com"},
				IPRanges:   []string{"127.0.0.1/32"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Policy{
				Allow:              tt.fields.Allow,
				Deny:               tt.fields.Deny,
				AllowWildcardNames: tt.fields.AllowWildcardNames,
			}
			if got := p.normalizeDenyRules(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Policy.normalizeDenyRules() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPolicy_normalizeRules(t *testing.T) {
	tests := []struct {
		name   string
		policy *Policy
		want   *provisioner.X509Options
	}{
		{
			name:   "'nil' policy results in 'nil' options",
			policy: nil,
			want:   nil,
		},
		{
			name: "'nil' Allow/Deny rules and disallowing wildcard names result in 'nil' X509Options",
			policy: &Policy{
				Allow:              nil,
				Deny:               nil,
				AllowWildcardNames: false,
			},
			want: nil,
		},
		{
			name: "'nil' Allow/Deny rules and allowing wildcard names result in 'nil' Allow/Deny rules in X509Options but allowing wildcard names in X509Options",
			policy: &Policy{
				Allow:              nil,
				Deny:               nil,
				AllowWildcardNames: true,
			},
			want: &provisioner.X509Options{
				AllowWildcardNames: true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.policy.normalizeRules(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Policy.normalizeRules() = %v, want %v", got, tt.want)
			}
		})
	}
}
