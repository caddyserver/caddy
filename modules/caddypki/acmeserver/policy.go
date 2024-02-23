package acmeserver

import (
	"github.com/smallstep/certificates/authority/policy"
	"github.com/smallstep/certificates/authority/provisioner"
)

// RuleSet is the specific set of SAN criteria for a certificate
// to be issued or denied.
type RuleSet struct {
	DNSDomains []string `json:"dns_domains,omitempty"`
	IPRanges   []string `json:"ip_ranges,omitempty"`
}

// Policy defines the criteria for the ACME server
// of when to issue a certificate. Refer to the
// [Certificate Issuance Policy](https://smallstep.com/docs/step-ca/policies/)
// on Smallstep website for the evaluation criteria.
type Policy struct {
	// If a rule set is configured to allow a certain type of name,
	// all other types of names are automatically denied.
	Allow *RuleSet `json:"allow,omitempty"`

	// If a rule set is configured to deny a certain type of name,
	// all other types of names are still allowed.
	Deny *RuleSet `json:"deny,omitempty"`

	// If set to true, the ACME server will allow issuing wildcard certificates.
	AllowWildcardNames bool `json:"allow_wildcard_names,omitempty"`
}

// normalizeAllowRules returns `nil` if policy is nil, the `Allow` rule is `nil`,
// or all rules within the `Allow` rule are empty. Otherwise, it returns the X509NameOptions
// with the content of the `Allow` rule.
func (p *Policy) normalizeAllowRules() *policy.X509NameOptions {
	if (p == nil) || (p.Allow == nil) || (len(p.Allow.DNSDomains) == 0 && len(p.Allow.IPRanges) == 0) {
		return nil
	}
	return &policy.X509NameOptions{
		DNSDomains: p.Allow.DNSDomains,
		IPRanges:   p.Allow.IPRanges,
	}
}

// normalizeDenyRules returns `nil` if policy is nil, the `Deny` rule is `nil`,
// or all rules within the `Deny` rule are empty. Otherwise, it returns the X509NameOptions
// with the content of the `Deny` rule.
func (p *Policy) normalizeDenyRules() *policy.X509NameOptions {
	if (p == nil) || (p.Deny == nil) || (len(p.Deny.DNSDomains) == 0 && len(p.Deny.IPRanges) == 0) {
		return nil
	}
	return &policy.X509NameOptions{
		DNSDomains: p.Deny.DNSDomains,
		IPRanges:   p.Deny.IPRanges,
	}
}

// normalizeRules returns `nil` if policy is nil, the `Allow` and `Deny` rules are `nil`,
func (p *Policy) normalizeRules() *provisioner.X509Options {
	if p == nil {
		return nil
	}

	allow := p.normalizeAllowRules()
	deny := p.normalizeDenyRules()
	if allow == nil && deny == nil && !p.AllowWildcardNames {
		return nil
	}

	return &provisioner.X509Options{
		AllowedNames:       allow,
		DeniedNames:        deny,
		AllowWildcardNames: p.AllowWildcardNames,
	}
}
