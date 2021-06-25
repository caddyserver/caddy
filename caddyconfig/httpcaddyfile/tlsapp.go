// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package httpcaddyfile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/acme"
)

func (st ServerType) buildTLSApp(
	pairings []sbAddrAssociation,
	options map[string]interface{},
	warnings []caddyconfig.Warning,
) (*caddytls.TLS, []caddyconfig.Warning, error) {

	tlsApp := &caddytls.TLS{CertificatesRaw: make(caddy.ModuleMap)}
	var certLoaders []caddytls.CertificateLoader

	httpPort := strconv.Itoa(caddyhttp.DefaultHTTPPort)
	if hp, ok := options["http_port"].(int); ok {
		httpPort = strconv.Itoa(hp)
	}
	httpsPort := strconv.Itoa(caddyhttp.DefaultHTTPSPort)
	if hsp, ok := options["https_port"].(int); ok {
		httpsPort = strconv.Itoa(hsp)
	}

	// count how many server blocks have a TLS-enabled key with
	// no host, and find all hosts that share a server block with
	// a hostless key, so that they don't get forgotten/omitted
	// by auto-HTTPS (since they won't appear in route matchers)
	var serverBlocksWithTLSHostlessKey int
	httpsHostsSharedWithHostlessKey := make(map[string]struct{})
	for _, pair := range pairings {
		for _, sb := range pair.serverBlocks {
			for _, addr := range sb.keys {
				if addr.Host == "" {
					// this address has no hostname, but if it's explicitly set
					// to HTTPS, then we need to count it as being TLS-enabled
					if addr.Scheme == "https" || addr.Port == httpsPort {
						serverBlocksWithTLSHostlessKey++
					}
					// this server block has a hostless key, now
					// go through and add all the hosts to the set
					for _, otherAddr := range sb.keys {
						if otherAddr.Original == addr.Original {
							continue
						}
						if otherAddr.Host != "" && otherAddr.Scheme != "http" && otherAddr.Port != httpPort {
							httpsHostsSharedWithHostlessKey[otherAddr.Host] = struct{}{}
						}
					}
					break
				}
			}
		}
	}

	// a catch-all automation policy is used as a "default" for all subjects that
	// don't have custom configuration explicitly associated with them; this
	// is only to add if the global settings or defaults are non-empty
	catchAllAP, err := newBaseAutomationPolicy(options, warnings, false)
	if err != nil {
		return nil, warnings, err
	}
	if catchAllAP != nil {
		if tlsApp.Automation == nil {
			tlsApp.Automation = new(caddytls.AutomationConfig)
		}
		tlsApp.Automation.Policies = append(tlsApp.Automation.Policies, catchAllAP)
	}

	for _, p := range pairings {
		// avoid setting up TLS automation policies for a server that is HTTP-only
		if !listenersUseAnyPortOtherThan(p.addresses, httpPort) {
			continue
		}

		for _, sblock := range p.serverBlocks {
			// get values that populate an automation policy for this block
			ap, err := newBaseAutomationPolicy(options, warnings, true)
			if err != nil {
				return nil, warnings, err
			}

			sblockHosts := sblock.hostsFromKeys(false)
			if len(sblockHosts) == 0 && catchAllAP != nil {
				ap = catchAllAP
			}

			// on-demand tls
			if _, ok := sblock.pile["tls.on_demand"]; ok {
				ap.OnDemand = true
			}

			if keyTypeVals, ok := sblock.pile["tls.key_type"]; ok {
				ap.KeyType = keyTypeVals[0].Value.(string)
			}

			// certificate issuers
			if issuerVals, ok := sblock.pile["tls.cert_issuer"]; ok {
				var issuers []certmagic.Issuer
				for _, issuerVal := range issuerVals {
					issuers = append(issuers, issuerVal.Value.(certmagic.Issuer))
				}
				if ap == catchAllAP && !reflect.DeepEqual(ap.Issuers, issuers) {
					return nil, warnings, fmt.Errorf("automation policy from site block is also default/catch-all policy because of key without hostname, and the two are in conflict: %#v != %#v", ap.Issuers, issuers)
				}
				ap.Issuers = issuers
			}

			// custom bind host
			for _, cfgVal := range sblock.pile["bind"] {
				for _, iss := range ap.Issuers {
					// if an issuer was already configured and it is NOT an ACME issuer,
					// skip, since we intend to adjust only ACME issuers; ensure we
					// include any issuer that embeds/wraps an underlying ACME issuer
					var acmeIssuer *caddytls.ACMEIssuer
					if acmeWrapper, ok := iss.(acmeCapable); ok {
						acmeIssuer = acmeWrapper.GetACMEIssuer()
					}
					if acmeIssuer == nil {
						continue
					}

					// proceed to configure the ACME issuer's bind host, without
					// overwriting any existing settings
					if acmeIssuer.Challenges == nil {
						acmeIssuer.Challenges = new(caddytls.ChallengesConfig)
					}
					if acmeIssuer.Challenges.BindHost == "" {
						// only binding to one host is supported
						var bindHost string
						if bindHosts, ok := cfgVal.Value.([]string); ok && len(bindHosts) > 0 {
							bindHost = bindHosts[0]
						}
						acmeIssuer.Challenges.BindHost = bindHost
					}
				}
			}

			// first make sure this block is allowed to create an automation policy;
			// doing so is forbidden if it has a key with no host (i.e. ":443")
			// and if there is a different server block that also has a key with no
			// host -- since a key with no host matches any host, we need its
			// associated automation policy to have an empty Subjects list, i.e. no
			// host filter, which is indistinguishable between the two server blocks
			// because automation is not done in the context of a particular server...
			// this is an example of a poor mapping from Caddyfile to JSON but that's
			// the least-leaky abstraction I could figure out
			if len(sblockHosts) == 0 {
				if serverBlocksWithTLSHostlessKey > 1 {
					// this server block and at least one other has a key with no host,
					// making the two indistinguishable; it is misleading to define such
					// a policy within one server block since it actually will apply to
					// others as well
					return nil, warnings, fmt.Errorf("cannot make a TLS automation policy from a server block that has a host-less address when there are other TLS-enabled server block addresses lacking a host")
				}
				if catchAllAP == nil {
					// this server block has a key with no hosts, but there is not yet
					// a catch-all automation policy (probably because no global options
					// were set), so this one becomes it
					catchAllAP = ap
				}
			}

			// associate our new automation policy with this server block's hosts
			ap.Subjects = sblock.hostsFromKeysNotHTTP(httpPort)
			sort.Strings(ap.Subjects) // solely for deterministic test results

			// if a combination of public and internal names were given
			// for this same server block and no issuer was specified, we
			// need to separate them out in the automation policies so
			// that the internal names can use the internal issuer and
			// the other names can use the default/public/ACME issuer
			var ap2 *caddytls.AutomationPolicy
			if len(ap.Issuers) == 0 {
				var internal, external []string
				for _, s := range ap.Subjects {
					if !certmagic.SubjectQualifiesForCert(s) {
						return nil, warnings, fmt.Errorf("subject does not qualify for certificate: '%s'", s)
					}
					// we don't use certmagic.SubjectQualifiesForPublicCert() because of one nuance:
					// names like *.*.tld that may not qualify for a public certificate are actually
					// fine when used with OnDemand, since OnDemand (currently) does not obtain
					// wildcards (if it ever does, there will be a separate config option to enable
					// it that we would need to check here) since the hostname is known at handshake;
					// and it is unexpected to switch to internal issuer when the user wants to get
					// regular certificates on-demand for a class of certs like *.*.tld.
					if subjectQualifiesForPublicCert(ap, s) {
						external = append(external, s)
					} else {
						internal = append(internal, s)
					}
				}
				if len(external) > 0 && len(internal) > 0 {
					ap.Subjects = external
					apCopy := *ap
					ap2 = &apCopy
					ap2.Subjects = internal
					ap2.IssuersRaw = []json.RawMessage{caddyconfig.JSONModuleObject(caddytls.InternalIssuer{}, "module", "internal", &warnings)}
				}
			}
			if tlsApp.Automation == nil {
				tlsApp.Automation = new(caddytls.AutomationConfig)
			}
			tlsApp.Automation.Policies = append(tlsApp.Automation.Policies, ap)
			if ap2 != nil {
				tlsApp.Automation.Policies = append(tlsApp.Automation.Policies, ap2)
			}

			// certificate loaders
			if clVals, ok := sblock.pile["tls.cert_loader"]; ok {
				for _, clVal := range clVals {
					certLoaders = append(certLoaders, clVal.Value.(caddytls.CertificateLoader))
				}
			}
		}
	}

	// group certificate loaders by module name, then add to config
	if len(certLoaders) > 0 {
		loadersByName := make(map[string]caddytls.CertificateLoader)
		for _, cl := range certLoaders {
			name := caddy.GetModuleName(cl)
			// ugh... technically, we may have multiple FileLoader and FolderLoader
			// modules (because the tls directive returns one per occurrence), but
			// the config structure expects only one instance of each kind of loader
			// module, so we have to combine them... instead of enumerating each
			// possible cert loader module in a type switch, we can use reflection,
			// which works on any cert loaders that are slice types
			if reflect.TypeOf(cl).Kind() == reflect.Slice {
				combined := reflect.ValueOf(loadersByName[name])
				if !combined.IsValid() {
					combined = reflect.New(reflect.TypeOf(cl)).Elem()
				}
				clVal := reflect.ValueOf(cl)
				for i := 0; i < clVal.Len(); i++ {
					combined = reflect.Append(combined, clVal.Index(i))
				}
				loadersByName[name] = combined.Interface().(caddytls.CertificateLoader)
			}
		}
		for certLoaderName, loaders := range loadersByName {
			tlsApp.CertificatesRaw[certLoaderName] = caddyconfig.JSON(loaders, &warnings)
		}
	}

	// set any of the on-demand options, for if/when on-demand TLS is enabled
	if onDemand, ok := options["on_demand_tls"].(*caddytls.OnDemandConfig); ok {
		if tlsApp.Automation == nil {
			tlsApp.Automation = new(caddytls.AutomationConfig)
		}
		tlsApp.Automation.OnDemand = onDemand
	}

	// set the storage clean interval if configured
	if storageCleanInterval, ok := options["storage_clean_interval"].(caddy.Duration); ok {
		if tlsApp.Automation == nil {
			tlsApp.Automation = new(caddytls.AutomationConfig)
		}
		tlsApp.Automation.StorageCleanInterval = storageCleanInterval
	}

	// if any hostnames appear on the same server block as a key with
	// no host, they will not be used with route matchers because the
	// hostless key matches all hosts, therefore, it wouldn't be
	// considered for auto-HTTPS, so we need to make sure those hosts
	// are manually considered for managed certificates; we also need
	// to make sure that any of these names which are internal-only
	// get internal certificates by default rather than ACME
	var al caddytls.AutomateLoader
	internalAP := &caddytls.AutomationPolicy{
		IssuersRaw: []json.RawMessage{json.RawMessage(`{"module":"internal"}`)},
	}
	for h := range httpsHostsSharedWithHostlessKey {
		al = append(al, h)
		if !certmagic.SubjectQualifiesForPublicCert(h) {
			internalAP.Subjects = append(internalAP.Subjects, h)
		}
	}
	if len(al) > 0 {
		tlsApp.CertificatesRaw["automate"] = caddyconfig.JSON(al, &warnings)
	}
	if len(internalAP.Subjects) > 0 {
		if tlsApp.Automation == nil {
			tlsApp.Automation = new(caddytls.AutomationConfig)
		}
		tlsApp.Automation.Policies = append(tlsApp.Automation.Policies, internalAP)
	}

	// if there are any global options set for issuers (ACME ones in particular), make sure they
	// take effect in every automation policy that does not have any issuers
	if tlsApp.Automation != nil {
		globalEmail := options["email"]
		globalACMECA := options["acme_ca"]
		globalACMECARoot := options["acme_ca_root"]
		globalACMEDNS := options["acme_dns"]
		globalACMEEAB := options["acme_eab"]
		globalPreferredChains := options["preferred_chains"]
		hasGlobalACMEDefaults := globalEmail != nil || globalACMECA != nil || globalACMECARoot != nil || globalACMEDNS != nil || globalACMEEAB != nil || globalPreferredChains != nil
		if hasGlobalACMEDefaults {
			// for _, ap := range tlsApp.Automation.Policies {
			for i := 0; i < len(tlsApp.Automation.Policies); i++ {
				ap := tlsApp.Automation.Policies[i]
				if len(ap.Issuers) == 0 && automationPolicyHasAllPublicNames(ap) {
					// for public names, create default issuers which will later be filled in with configured global defaults
					// (internal names will implicitly use the internal issuer at auto-https time)
					ap.Issuers = caddytls.DefaultIssuers()

					// if a specific endpoint is configured, can't use multiple default issuers
					if globalACMECA != nil {
						if strings.Contains(globalACMECA.(string), "zerossl") {
							ap.Issuers = []certmagic.Issuer{&caddytls.ZeroSSLIssuer{ACMEIssuer: new(caddytls.ACMEIssuer)}}
						} else {
							ap.Issuers = []certmagic.Issuer{new(caddytls.ACMEIssuer)}
						}
					}
				}
			}
		}
	}

	// finalize and verify policies; do cleanup
	if tlsApp.Automation != nil {
		for i, ap := range tlsApp.Automation.Policies {
			// ensure all issuers have global defaults filled in
			for j, issuer := range ap.Issuers {
				err := fillInGlobalACMEDefaults(issuer, options)
				if err != nil {
					return nil, warnings, fmt.Errorf("filling in global issuer defaults for AP %d, issuer %d: %v", i, j, err)
				}
			}

			// encode all issuer values we created, so they will be rendered in the output
			if len(ap.Issuers) > 0 && ap.IssuersRaw == nil {
				for _, iss := range ap.Issuers {
					issuerName := iss.(caddy.Module).CaddyModule().ID.Name()
					ap.IssuersRaw = append(ap.IssuersRaw, caddyconfig.JSONModuleObject(iss, "module", issuerName, &warnings))
				}
			}
		}

		// consolidate automation policies that are the exact same
		tlsApp.Automation.Policies = consolidateAutomationPolicies(tlsApp.Automation.Policies)

		// ensure automation policies don't overlap subjects (this should be
		// an error at provision-time as well, but catch it in the adapt phase
		// for convenience)
		automationHostSet := make(map[string]struct{})
		for _, ap := range tlsApp.Automation.Policies {
			for _, s := range ap.Subjects {
				if _, ok := automationHostSet[s]; ok {
					return nil, warnings, fmt.Errorf("hostname appears in more than one automation policy, making certificate management ambiguous: %s", s)
				}
				automationHostSet[s] = struct{}{}
			}
		}

		// if nothing remains, remove any excess values to clean up the resulting config
		if len(tlsApp.Automation.Policies) == 0 {
			tlsApp.Automation.Policies = nil
		}
		if reflect.DeepEqual(tlsApp.Automation, new(caddytls.AutomationConfig)) {
			tlsApp.Automation = nil
		}
	}

	return tlsApp, warnings, nil
}

type acmeCapable interface{ GetACMEIssuer() *caddytls.ACMEIssuer }

func fillInGlobalACMEDefaults(issuer certmagic.Issuer, options map[string]interface{}) error {
	acmeWrapper, ok := issuer.(acmeCapable)
	if !ok {
		return nil
	}
	acmeIssuer := acmeWrapper.GetACMEIssuer()
	if acmeIssuer == nil {
		return nil
	}

	globalEmail := options["email"]
	globalACMECA := options["acme_ca"]
	globalACMECARoot := options["acme_ca_root"]
	globalACMEDNS := options["acme_dns"]
	globalACMEEAB := options["acme_eab"]
	globalPreferredChains := options["preferred_chains"]

	if globalEmail != nil && acmeIssuer.Email == "" {
		acmeIssuer.Email = globalEmail.(string)
	}
	if globalACMECA != nil && acmeIssuer.CA == "" {
		acmeIssuer.CA = globalACMECA.(string)
	}
	if globalACMECARoot != nil && !sliceContains(acmeIssuer.TrustedRootsPEMFiles, globalACMECARoot.(string)) {
		acmeIssuer.TrustedRootsPEMFiles = append(acmeIssuer.TrustedRootsPEMFiles, globalACMECARoot.(string))
	}
	if globalACMEDNS != nil && (acmeIssuer.Challenges == nil || acmeIssuer.Challenges.DNS == nil) {
		acmeIssuer.Challenges = &caddytls.ChallengesConfig{
			DNS: &caddytls.DNSChallengeConfig{
				ProviderRaw: caddyconfig.JSONModuleObject(globalACMEDNS, "name", globalACMEDNS.(caddy.Module).CaddyModule().ID.Name(), nil),
			},
		}
	}
	if globalACMEEAB != nil && acmeIssuer.ExternalAccount == nil {
		acmeIssuer.ExternalAccount = globalACMEEAB.(*acme.EAB)
	}
	if globalPreferredChains != nil && acmeIssuer.PreferredChains == nil {
		acmeIssuer.PreferredChains = globalPreferredChains.(*caddytls.ChainPreference)
	}
	return nil
}

// newBaseAutomationPolicy returns a new TLS automation policy that gets
// its values from the global options map. It should be used as the base
// for any other automation policies. A nil policy (and no error) will be
// returned if there are no default/global options. However, if always is
// true, a non-nil value will always be returned (unless there is an error).
func newBaseAutomationPolicy(options map[string]interface{}, warnings []caddyconfig.Warning, always bool) (*caddytls.AutomationPolicy, error) {
	issuers, hasIssuers := options["cert_issuer"]
	_, hasLocalCerts := options["local_certs"]
	keyType, hasKeyType := options["key_type"]
	ocspStapling, hasOCSPStapling := options["ocsp_stapling"]

	hasGlobalAutomationOpts := hasIssuers || hasLocalCerts || hasKeyType || hasOCSPStapling

	// if there are no global options related to automation policies
	// set, then we can just return right away
	if !hasGlobalAutomationOpts {
		if always {
			return new(caddytls.AutomationPolicy), nil
		}
		return nil, nil
	}

	ap := new(caddytls.AutomationPolicy)
	if hasKeyType {
		ap.KeyType = keyType.(string)
	}

	if hasIssuers && hasLocalCerts {
		return nil, fmt.Errorf("global options are ambiguous: local_certs is confusing when combined with cert_issuer, because local_certs is also a specific kind of issuer")
	}

	if hasIssuers {
		ap.Issuers = issuers.([]certmagic.Issuer)
	} else if hasLocalCerts {
		ap.Issuers = []certmagic.Issuer{new(caddytls.InternalIssuer)}
	}

	if hasOCSPStapling {
		ocspConfig := ocspStapling.(certmagic.OCSPConfig)
		ap.DisableOCSPStapling = ocspConfig.DisableStapling
		ap.OCSPOverrides = ocspConfig.ResponderOverrides
	}

	return ap, nil
}

// consolidateAutomationPolicies combines automation policies that are the same,
// for a cleaner overall output.
func consolidateAutomationPolicies(aps []*caddytls.AutomationPolicy) []*caddytls.AutomationPolicy {
	// sort from most specific to least specific; we depend on this ordering
	sort.SliceStable(aps, func(i, j int) bool {
		if automationPolicyIsSubset(aps[i], aps[j]) {
			return true
		}
		if automationPolicyIsSubset(aps[j], aps[i]) {
			return false
		}
		return len(aps[i].Subjects) > len(aps[j].Subjects)
	})

	emptyAPCount := 0
	origLenAPs := len(aps)
	// compute the number of empty policies (disregarding subjects) - see #4128
	emptyAP := new(caddytls.AutomationPolicy)
	for i := 0; i < len(aps); i++ {
		emptyAP.Subjects = aps[i].Subjects
		if reflect.DeepEqual(aps[i], emptyAP) {
			emptyAPCount++
			if !automationPolicyHasAllPublicNames(aps[i]) {
				// if this automation policy has internal names, we might as well remove it
				// so auto-https can implicitly use the internal issuer
				aps = append(aps[:i], aps[i+1:]...)
				i--
			}
		}
	}
	// If all policies are empty, we can return nil, as there is no need to set any policy
	if emptyAPCount == origLenAPs {
		return nil
	}

	// remove or combine duplicate policies
outer:
	for i := 0; i < len(aps); i++ {
		// compare only with next policies; we sorted by specificity so we must not delete earlier policies
		for j := i + 1; j < len(aps); j++ {
			// if they're exactly equal in every way, just keep one of them
			if reflect.DeepEqual(aps[i], aps[j]) {
				aps = append(aps[:j], aps[j+1:]...)
				// must re-evaluate current i against next j; can't skip it!
				// even if i decrements to -1, will be incremented to 0 immediately
				i--
				continue outer
			}

			// if the policy is the same, we can keep just one, but we have
			// to be careful which one we keep; if only one has any hostnames
			// defined, then we need to keep the one without any hostnames,
			// otherwise the one without any subjects (a catch-all) would be
			// eaten up by the one with subjects; and if both have subjects, we
			// need to combine their lists
			if reflect.DeepEqual(aps[i].IssuersRaw, aps[j].IssuersRaw) &&
				bytes.Equal(aps[i].StorageRaw, aps[j].StorageRaw) &&
				aps[i].MustStaple == aps[j].MustStaple &&
				aps[i].KeyType == aps[j].KeyType &&
				aps[i].OnDemand == aps[j].OnDemand &&
				aps[i].RenewalWindowRatio == aps[j].RenewalWindowRatio {
				if len(aps[i].Subjects) > 0 && len(aps[j].Subjects) == 0 {
					// later policy (at j) has no subjects ("catch-all"), so we can
					// remove the identical-but-more-specific policy that comes first
					// AS LONG AS it is not shadowed by another policy before it; e.g.
					// if policy i is for example.com, policy i+1 is '*.com', and policy
					// j is catch-all, we cannot remove policy i because that would
					// cause example.com to be served by the less specific policy for
					// '*.com', which might be different (yes we've seen this happen)
					if automationPolicyShadows(i, aps) >= j {
						aps = append(aps[:i], aps[i+1:]...)
						i--
						continue outer
					}
				} else {
					// avoid repeated subjects
					for _, subj := range aps[j].Subjects {
						if !sliceContains(aps[i].Subjects, subj) {
							aps[i].Subjects = append(aps[i].Subjects, subj)
						}
					}
					aps = append(aps[:j], aps[j+1:]...)
					j--
				}
			}
		}
	}

	return aps
}

// automationPolicyIsSubset returns true if a's subjects are a subset
// of b's subjects.
func automationPolicyIsSubset(a, b *caddytls.AutomationPolicy) bool {
	if len(b.Subjects) == 0 {
		return true
	}
	if len(a.Subjects) == 0 {
		return false
	}
	for _, aSubj := range a.Subjects {
		var inSuperset bool
		for _, bSubj := range b.Subjects {
			if certmagic.MatchWildcard(aSubj, bSubj) {
				inSuperset = true
				break
			}
		}
		if !inSuperset {
			return false
		}
	}
	return true
}

// automationPolicyShadows returns the index of a policy that aps[i] shadows;
// in other words, for all policies after position i, if that policy covers
// the same subjects but is less specific, that policy's position is returned,
// or -1 if no shadowing is found. For example, if policy i is for
// "foo.example.com" and policy i+2 is for "*.example.com", then i+2 will be
// returned, since that policy is shadowed by i, which is in front.
func automationPolicyShadows(i int, aps []*caddytls.AutomationPolicy) int {
	for j := i + 1; j < len(aps); j++ {
		if automationPolicyIsSubset(aps[i], aps[j]) {
			return j
		}
	}
	return -1
}

// subjectQualifiesForPublicCert is like certmagic.SubjectQualifiesForPublicCert() except
// that this allows domains with multiple wildcard levels like '*.*.example.com' to qualify
// if the automation policy has OnDemand enabled (i.e. this function is more lenient).
func subjectQualifiesForPublicCert(ap *caddytls.AutomationPolicy, subj string) bool {
	return !certmagic.SubjectIsIP(subj) &&
		!certmagic.SubjectIsInternal(subj) &&
		(strings.Count(subj, "*.") < 2 || ap.OnDemand)
}

func automationPolicyHasAllPublicNames(ap *caddytls.AutomationPolicy) bool {
	for _, subj := range ap.Subjects {
		if !subjectQualifiesForPublicCert(ap, subj) {
			return false
		}
	}
	return true
}
