package acmeserver

import (
	"github.com/smallstep/certificates/authority/policy"
	"github.com/smallstep/certificates/authority/provisioner"
)

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

// RuleSet is the specific set of SAN criteria for a certificate
// to be issued or denied.
type RuleSet struct {
	// Domains is a list of DNS domains that are allowed to be issued.
	// It can be in the form of FQDN for specific domain name, or
	// a wildcard domain name format, e.g. *.example.com, to allow
	// sub-domains of a domain.
	Domains []string `json:"domains,omitempty"`

	// IP ranges in the form of CIDR notation or specific IP addresses
	// to be approved or denied for certificates. Non-CIDR IP addresses
	// are matched exactly.
	IPRanges []string `json:"ip_ranges,omitempty"`
}

// normalizeAllowRules returns `nil` if policy is nil, the `Allow` rule is `nil`,
// or all rules within the `Allow` rule are empty. Otherwise, it returns the X509NameOptions
// with the content of the `Allow` rule.
func (p *Policy) normalizeAllowRules() *policy.X509NameOptions {
	if (p == nil) || (p.Allow == nil) || (len(p.Allow.Domains) == 0 && len(p.Allow.IPRanges) == 0) {
		return nil
	}
	return &policy.X509NameOptions{
		DNSDomains: p.Allow.Domains,
		IPRanges:   p.Allow.IPRanges,
	}
}

// normalizeDenyRules returns `nil` if policy is nil, the `Deny` rule is `nil`,
// or all rules within the `Deny` rule are empty. Otherwise, it returns the X509NameOptions
// with the content of the `Deny` rule.
func (p *Policy) normalizeDenyRules() *policy.X509NameOptions {
	if (p == nil) || (p.Deny == nil) || (len(p.Deny.Domains) == 0 && len(p.Deny.IPRanges) == 0) {
		return nil
	}
	return &policy.X509NameOptions{
		DNSDomains: p.Deny.Domains,
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
