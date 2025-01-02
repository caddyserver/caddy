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
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v3/acme"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

func (st ServerType) buildTLSApp(
	pairings []sbAddrAssociation,
	options map[string]any,
	warnings []caddyconfig.Warning,
) (*caddytls.TLS, []caddyconfig.Warning, error) {
	tlsApp := &caddytls.TLS{CertificatesRaw: make(caddy.ModuleMap)}
	var certLoaders []caddytls.CertificateLoader

	httpPort := strconv.Itoa(caddyhttp.DefaultHTTPPort)
	if hp, ok := options["http_port"].(int); ok {
		httpPort = strconv.Itoa(hp)
	}
	autoHTTPS := []string{}
	if ah, ok := options["auto_https"].([]string); ok {
		autoHTTPS = ah
	}

	// find all hosts that share a server block with a hostless
	// key, so that they don't get forgotten/omitted by auto-HTTPS
	// (since they won't appear in route matchers)
	httpsHostsSharedWithHostlessKey := make(map[string]struct{})
	if !slices.Contains(autoHTTPS, "off") {
		for _, pair := range pairings {
			for _, sb := range pair.serverBlocks {
				for _, addr := range sb.parsedKeys {
					if addr.Host != "" {
						continue
					}

					// this server block has a hostless key, now
					// go through and add all the hosts to the set
					for _, otherAddr := range sb.parsedKeys {
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

	// collect all hosts that have a wildcard in them, and arent HTTP
	wildcardHosts := []string{}
	// hosts that have been explicitly marked to be automated,
	// even if covered by another wildcard
	forcedAutomatedNames := make(map[string]struct{})
	for _, p := range pairings {
		var addresses []string
		for _, addressWithProtocols := range p.addressesWithProtocols {
			addresses = append(addresses, addressWithProtocols.address)
		}
		if !listenersUseAnyPortOtherThan(addresses, httpPort) {
			continue
		}
		for _, sblock := range p.serverBlocks {
			for _, addr := range sblock.parsedKeys {
				if strings.HasPrefix(addr.Host, "*.") {
					wildcardHosts = append(wildcardHosts, addr.Host[2:])
				}
			}
		}
	}

	for _, p := range pairings {
		// avoid setting up TLS automation policies for a server that is HTTP-only
		var addresses []string
		for _, addressWithProtocols := range p.addressesWithProtocols {
			addresses = append(addresses, addressWithProtocols.address)
		}
		if !listenersUseAnyPortOtherThan(addresses, httpPort) {
			continue
		}

		for _, sblock := range p.serverBlocks {
			// check the scheme of all the site addresses,
			// skip building AP if they all had http://
			if sblock.isAllHTTP() {
				continue
			}

			// get values that populate an automation policy for this block
			ap, err := newBaseAutomationPolicy(options, warnings, true)
			if err != nil {
				return nil, warnings, err
			}

			// make a plain copy so we can compare whether we made any changes
			apCopy, err := newBaseAutomationPolicy(options, warnings, true)
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

			// collect hosts that are forced to be automated
			if _, ok := sblock.pile["tls.force_automate"]; ok {
				for _, host := range sblockHosts {
					forcedAutomatedNames[host] = struct{}{}
				}
			}

			// reuse private keys tls
			if _, ok := sblock.pile["tls.reuse_private_keys"]; ok {
				ap.ReusePrivateKeys = true
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
					// this more correctly implements an error check that was removed
					// below; try it with this config:
					//
					// :443 {
					// 	bind 127.0.0.1
					// }
					//
					// :443 {
					// 	bind ::1
					// 	tls {
					// 		issuer acme
					// 	}
					// }
					return nil, warnings, fmt.Errorf("automation policy from site block is also default/catch-all policy because of key without hostname, and the two are in conflict: %#v != %#v", ap.Issuers, issuers)
				}
				ap.Issuers = issuers
			}

			// certificate managers
			if certManagerVals, ok := sblock.pile["tls.cert_manager"]; ok {
				for _, certManager := range certManagerVals {
					certGetterName := certManager.Value.(caddy.Module).CaddyModule().ID.Name()
					ap.ManagersRaw = append(ap.ManagersRaw, caddyconfig.JSONModuleObject(certManager.Value, "via", certGetterName, &warnings))
				}
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
						if asserted, ok := cfgVal.Value.(addressesWithProtocols); ok && len(asserted.addresses) > 0 {
							bindHost = asserted.addresses[0]
						}
						acmeIssuer.Challenges.BindHost = bindHost
					}
				}
			}

			// we used to ensure this block is allowed to create an automation policy;
			// doing so was forbidden if it has a key with no host (i.e. ":443")
			// and if there is a different server block that also has a key with no
			// host -- since a key with no host matches any host, we need its
			// associated automation policy to have an empty Subjects list, i.e. no
			// host filter, which is indistinguishable between the two server blocks
			// because automation is not done in the context of a particular server...
			// this is an example of a poor mapping from Caddyfile to JSON but that's
			// the least-leaky abstraction I could figure out -- however, this check
			// was preventing certain listeners, like those provided by plugins, from
			// being used as desired (see the Tailscale listener plugin), so I removed
			// the check: and I think since I originally wrote the check I added a new
			// check above which *properly* detects this ambiguity without breaking the
			// listener plugin; see the check above with a commented example config
			if len(sblockHosts) == 0 && catchAllAP == nil {
				// this server block has a key with no hosts, but there is not yet
				// a catch-all automation policy (probably because no global options
				// were set), so this one becomes it
				catchAllAP = ap
			}

			hostsNotHTTP := sblock.hostsFromKeysNotHTTP(httpPort)
			sort.Strings(hostsNotHTTP) // solely for deterministic test results

			// if the we prefer wildcards and the AP is unchanged,
			// then we can skip this AP because it should be covered
			// by an AP with a wildcard
			if slices.Contains(autoHTTPS, "prefer_wildcard") {
				if hostsCoveredByWildcard(hostsNotHTTP, wildcardHosts) &&
					reflect.DeepEqual(ap, apCopy) {
					continue
				}
			}

			// associate our new automation policy with this server block's hosts
			ap.SubjectsRaw = hostsNotHTTP

			// if a combination of public and internal names were given
			// for this same server block and no issuer was specified, we
			// need to separate them out in the automation policies so
			// that the internal names can use the internal issuer and
			// the other names can use the default/public/ACME issuer
			var ap2 *caddytls.AutomationPolicy
			if len(ap.Issuers) == 0 {
				var internal, external []string
				for _, s := range ap.SubjectsRaw {
					// do not create Issuers for Tailscale domains; they will be given a Manager instead
					if isTailscaleDomain(s) {
						continue
					}
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
					ap.SubjectsRaw = external
					apCopy := *ap
					ap2 = &apCopy
					ap2.SubjectsRaw = internal
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

	// if the storage clean interval is a boolean, then it's "off" to disable cleaning
	if sc, ok := options["storage_check"].(string); ok && sc == "off" {
		tlsApp.DisableStorageCheck = true
	}

	// if the storage clean interval is a boolean, then it's "off" to disable cleaning
	if sci, ok := options["storage_clean_interval"].(bool); ok && !sci {
		tlsApp.DisableStorageClean = true
	}

	// set the storage clean interval if configured
	if storageCleanInterval, ok := options["storage_clean_interval"].(caddy.Duration); ok {
		if tlsApp.Automation == nil {
			tlsApp.Automation = new(caddytls.AutomationConfig)
		}
		tlsApp.Automation.StorageCleanInterval = storageCleanInterval
	}

	// set the expired certificates renew interval if configured
	if renewCheckInterval, ok := options["renew_interval"].(caddy.Duration); ok {
		if tlsApp.Automation == nil {
			tlsApp.Automation = new(caddytls.AutomationConfig)
		}
		tlsApp.Automation.RenewCheckInterval = renewCheckInterval
	}

	// set the OCSP check interval if configured
	if ocspCheckInterval, ok := options["ocsp_interval"].(caddy.Duration); ok {
		if tlsApp.Automation == nil {
			tlsApp.Automation = new(caddytls.AutomationConfig)
		}
		tlsApp.Automation.OCSPCheckInterval = ocspCheckInterval
	}

	// set whether OCSP stapling should be disabled for manually-managed certificates
	if ocspConfig, ok := options["ocsp_stapling"].(certmagic.OCSPConfig); ok {
		tlsApp.DisableOCSPStapling = ocspConfig.DisableStapling
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
	if !slices.Contains(autoHTTPS, "off") && !slices.Contains(autoHTTPS, "disable_certs") {
		for h := range httpsHostsSharedWithHostlessKey {
			al = append(al, h)
			if !certmagic.SubjectQualifiesForPublicCert(h) {
				internalAP.SubjectsRaw = append(internalAP.SubjectsRaw, h)
			}
		}
	}
	for name := range forcedAutomatedNames {
		if slices.Contains(al, name) {
			continue
		}
		al = append(al, name)
	}
	slices.Sort(al) // to stabilize the adapt output
	if len(al) > 0 {
		tlsApp.CertificatesRaw["automate"] = caddyconfig.JSON(al, &warnings)
	}
	if len(internalAP.SubjectsRaw) > 0 {
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
			for i := 0; i < len(tlsApp.Automation.Policies); i++ {
				ap := tlsApp.Automation.Policies[i]
				if len(ap.Issuers) == 0 && automationPolicyHasAllPublicNames(ap) {
					// for public names, create default issuers which will later be filled in with configured global defaults
					// (internal names will implicitly use the internal issuer at auto-https time)
					emailStr, _ := globalEmail.(string)
					ap.Issuers = caddytls.DefaultIssuers(emailStr)

					// if a specific endpoint is configured, can't use multiple default issuers
					if globalACMECA != nil {
						ap.Issuers = []certmagic.Issuer{new(caddytls.ACMEIssuer)}
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
			for _, s := range ap.SubjectsRaw {
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

func fillInGlobalACMEDefaults(issuer certmagic.Issuer, options map[string]any) error {
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
	globalCertLifetime := options["cert_lifetime"]
	globalHTTPPort, globalHTTPSPort := options["http_port"], options["https_port"]

	if globalEmail != nil && acmeIssuer.Email == "" {
		acmeIssuer.Email = globalEmail.(string)
	}
	if globalACMECA != nil && acmeIssuer.CA == "" {
		acmeIssuer.CA = globalACMECA.(string)
	}
	if globalACMECARoot != nil && !slices.Contains(acmeIssuer.TrustedRootsPEMFiles, globalACMECARoot.(string)) {
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
	if globalHTTPPort != nil && (acmeIssuer.Challenges == nil || acmeIssuer.Challenges.HTTP == nil || acmeIssuer.Challenges.HTTP.AlternatePort == 0) {
		if acmeIssuer.Challenges == nil {
			acmeIssuer.Challenges = new(caddytls.ChallengesConfig)
		}
		if acmeIssuer.Challenges.HTTP == nil {
			acmeIssuer.Challenges.HTTP = new(caddytls.HTTPChallengeConfig)
		}
		acmeIssuer.Challenges.HTTP.AlternatePort = globalHTTPPort.(int)
	}
	if globalHTTPSPort != nil && (acmeIssuer.Challenges == nil || acmeIssuer.Challenges.TLSALPN == nil || acmeIssuer.Challenges.TLSALPN.AlternatePort == 0) {
		if acmeIssuer.Challenges == nil {
			acmeIssuer.Challenges = new(caddytls.ChallengesConfig)
		}
		if acmeIssuer.Challenges.TLSALPN == nil {
			acmeIssuer.Challenges.TLSALPN = new(caddytls.TLSALPNChallengeConfig)
		}
		acmeIssuer.Challenges.TLSALPN.AlternatePort = globalHTTPSPort.(int)
	}
	if globalCertLifetime != nil && acmeIssuer.CertificateLifetime == 0 {
		acmeIssuer.CertificateLifetime = globalCertLifetime.(caddy.Duration)
	}
	return nil
}

// newBaseAutomationPolicy returns a new TLS automation policy that gets
// its values from the global options map. It should be used as the base
// for any other automation policies. A nil policy (and no error) will be
// returned if there are no default/global options. However, if always is
// true, a non-nil value will always be returned (unless there is an error).
func newBaseAutomationPolicy(
	options map[string]any,
	_ []caddyconfig.Warning,
	always bool,
) (*caddytls.AutomationPolicy, error) {
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
		return len(aps[i].SubjectsRaw) > len(aps[j].SubjectsRaw)
	})

	emptyAPCount := 0
	origLenAPs := len(aps)
	// compute the number of empty policies (disregarding subjects) - see #4128
	emptyAP := new(caddytls.AutomationPolicy)
	for i := 0; i < len(aps); i++ {
		emptyAP.SubjectsRaw = aps[i].SubjectsRaw
		if reflect.DeepEqual(aps[i], emptyAP) {
			emptyAPCount++
			if !automationPolicyHasAllPublicNames(aps[i]) {
				// if this automation policy has internal names, we might as well remove it
				// so auto-https can implicitly use the internal issuer
				aps = slices.Delete(aps, i, i+1)
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
				aps = slices.Delete(aps, j, j+1)
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
				reflect.DeepEqual(aps[i].ManagersRaw, aps[j].ManagersRaw) &&
				bytes.Equal(aps[i].StorageRaw, aps[j].StorageRaw) &&
				aps[i].MustStaple == aps[j].MustStaple &&
				aps[i].KeyType == aps[j].KeyType &&
				aps[i].OnDemand == aps[j].OnDemand &&
				aps[i].ReusePrivateKeys == aps[j].ReusePrivateKeys &&
				aps[i].RenewalWindowRatio == aps[j].RenewalWindowRatio {
				if len(aps[i].SubjectsRaw) > 0 && len(aps[j].SubjectsRaw) == 0 {
					// later policy (at j) has no subjects ("catch-all"), so we can
					// remove the identical-but-more-specific policy that comes first
					// AS LONG AS it is not shadowed by another policy before it; e.g.
					// if policy i is for example.com, policy i+1 is '*.com', and policy
					// j is catch-all, we cannot remove policy i because that would
					// cause example.com to be served by the less specific policy for
					// '*.com', which might be different (yes we've seen this happen)
					if automationPolicyShadows(i, aps) >= j {
						aps = slices.Delete(aps, i, i+1)
						i--
						continue outer
					}
				} else {
					// avoid repeated subjects
					for _, subj := range aps[j].SubjectsRaw {
						if !slices.Contains(aps[i].SubjectsRaw, subj) {
							aps[i].SubjectsRaw = append(aps[i].SubjectsRaw, subj)
						}
					}
					aps = slices.Delete(aps, j, j+1)
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
	if len(b.SubjectsRaw) == 0 {
		return true
	}
	if len(a.SubjectsRaw) == 0 {
		return false
	}
	for _, aSubj := range a.SubjectsRaw {
		inSuperset := slices.ContainsFunc(b.SubjectsRaw, func(bSubj string) bool {
			return certmagic.MatchWildcard(aSubj, bSubj)
		})
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
//
// IP subjects are considered as non-qualifying for public certs. Technically, there are
// now public ACME CAs as well as non-ACME CAs that issue IP certificates. But this function
// is used solely for implicit automation (defaults), where it gets really complicated to
// keep track of which issuers support IP certificates in which circumstances. Currently,
// issuers that support IP certificates are very few, and all require some sort of config
// from the user anyway (such as an account credential). Since we cannot implicitly and
// automatically get public IP certs without configuration from the user, we treat IPs as
// not qualifying for public certificates. Users should expressly configure an issuer
// that supports IP certs for that purpose.
func subjectQualifiesForPublicCert(ap *caddytls.AutomationPolicy, subj string) bool {
	return !certmagic.SubjectIsIP(subj) &&
		!certmagic.SubjectIsInternal(subj) &&
		(strings.Count(subj, "*.") < 2 || ap.OnDemand)
}

// automationPolicyHasAllPublicNames returns true if all the names on the policy
// do NOT qualify for public certs OR are tailscale domains.
func automationPolicyHasAllPublicNames(ap *caddytls.AutomationPolicy) bool {
	return !slices.ContainsFunc(ap.SubjectsRaw, func(i string) bool {
		return !subjectQualifiesForPublicCert(ap, i) || isTailscaleDomain(i)
	})
}

func isTailscaleDomain(name string) bool {
	return strings.HasSuffix(strings.ToLower(name), ".ts.net")
}

func hostsCoveredByWildcard(hosts []string, wildcards []string) bool {
	if len(hosts) == 0 || len(wildcards) == 0 {
		return false
	}
	for _, host := range hosts {
		for _, wildcard := range wildcards {
			if strings.HasPrefix(host, "*.") {
				continue
			}
			if certmagic.MatchWildcard(host, "*."+wildcard) {
				return true
			}
		}
	}
	return false
}
