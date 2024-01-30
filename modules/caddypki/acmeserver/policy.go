package acmeserver

import (
	"github.com/smallstep/certificates/authority/policy"
	"github.com/smallstep/certificates/authority/provisioner"
)

type Rule struct {
	CommonNames []string `json:"common_names,omitempty"`
	DNSDomains  []string `json:"dns_domains,omitempty"`
	IPRanges    []string `json:"ip_ranges,omitempty"`
}

type Policy struct {
	Allow              *Rule `json:"allow,omitempty"`
	Deny               *Rule `json:"deny,omitempty"`
	AllowWildcardNames bool  `json:"allow_wildcard_names,omitempty"`
}

func (p *Policy) normalizeAllowRules() *policy.X509NameOptions {
	if (p == nil) || (p.Allow == nil) || (len(p.Allow.CommonNames) == 0 && len(p.Allow.DNSDomains) == 0 && len(p.Allow.IPRanges) == 0) {
		return nil
	}
	return &policy.X509NameOptions{
		CommonNames: p.Allow.CommonNames,
		DNSDomains:  p.Allow.DNSDomains,
		IPRanges:    p.Allow.IPRanges,
	}
}

func (p *Policy) normalizeDenyRules() *policy.X509NameOptions {
	if (p == nil) || (p.Deny == nil) || (len(p.Deny.CommonNames) == 0 && len(p.Deny.DNSDomains) == 0 && len(p.Deny.IPRanges) == 0) {
		return nil
	}
	return &policy.X509NameOptions{
		CommonNames: p.Deny.CommonNames,
		DNSDomains:  p.Deny.DNSDomains,
		IPRanges:    p.Deny.IPRanges,
	}
}

func (p *Policy) normalizeRules() *provisioner.X509Options {
	allow := p.normalizeAllowRules()
	deny := p.normalizeDenyRules()

	if p == nil || allow == nil && deny == nil && !p.AllowWildcardNames {
		return nil
	}

	return &provisioner.X509Options{
		AllowedNames:       allow,
		DeniedNames:        deny,
		AllowWildcardNames: p.AllowWildcardNames,
	}
}
