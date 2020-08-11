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

	httpsPort := strconv.Itoa(caddyhttp.DefaultHTTPSPort)
	if hsp, ok := options["https_port"].(int); ok {
		httpsPort = strconv.Itoa(hsp)
	}

	// count how many server blocks have a TLS-enabled key with
	// no host, and find all hosts that share a server block with
	// a hostless key, so that they don't get forgotten/omitted
	// by auto-HTTPS (since they won't appear in route matchers)
	var serverBlocksWithTLSHostlessKey int
	hostsSharedWithHostlessKey := make(map[string]struct{})
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
						if otherAddr.Host != "" {
							hostsSharedWithHostlessKey[otherAddr.Host] = struct{}{}
						}
					}
					break
				}
			}
		}
	}

	catchAllAP, err := newBaseAutomationPolicy(options, warnings, false)
	if err != nil {
		return nil, warnings, err
	}

	for _, p := range pairings {
		for _, sblock := range p.serverBlocks {
			// get values that populate an automation policy for this block
			var ap *caddytls.AutomationPolicy

			sblockHosts := sblock.hostsFromKeys(false)
			if len(sblockHosts) == 0 {
				ap = catchAllAP
			}

			// on-demand tls
			if _, ok := sblock.pile["tls.on_demand"]; ok {
				if ap == nil {
					var err error
					ap, err = newBaseAutomationPolicy(options, warnings, true)
					if err != nil {
						return nil, warnings, err
					}
				}
				ap.OnDemand = true
			}

			// certificate issuers
			if issuerVals, ok := sblock.pile["tls.cert_issuer"]; ok {
				for _, issuerVal := range issuerVals {
					issuer := issuerVal.Value.(certmagic.Issuer)
					if ap == nil {
						var err error
						ap, err = newBaseAutomationPolicy(options, warnings, true)
						if err != nil {
							return nil, warnings, err
						}
					}
					if ap == catchAllAP && !reflect.DeepEqual(ap.Issuer, issuer) {
						return nil, warnings, fmt.Errorf("automation policy from site block is also default/catch-all policy because of key without hostname, and the two are in conflict: %#v != %#v", ap.Issuer, issuer)
					}
					ap.Issuer = issuer
				}
			}

			// custom bind host
			for _, cfgVal := range sblock.pile["bind"] {
				// either an existing issuer is already configured (and thus, ap is not
				// nil), or we need to configure an issuer, so we need ap to be non-nil
				if ap == nil {
					ap, err = newBaseAutomationPolicy(options, warnings, true)
					if err != nil {
						return nil, warnings, err
					}
				}

				// if an issuer was already configured and it is NOT an ACME
				// issuer, skip, since we intend to adjust only ACME issuers
				var acmeIssuer *caddytls.ACMEIssuer
				if ap.Issuer != nil {
					// ensure we include any issuer that embeds/wraps an underlying ACME issuer
					type acmeCapable interface{ GetACMEIssuer() *caddytls.ACMEIssuer }
					if acmeWrapper, ok := ap.Issuer.(acmeCapable); ok {
						acmeIssuer = acmeWrapper.GetACMEIssuer()
					} else {
						break
					}
				}

				// proceed to configure the ACME issuer's bind host, without
				// overwriting any existing settings
				if acmeIssuer == nil {
					acmeIssuer = new(caddytls.ACMEIssuer)
				}
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
				ap.Issuer = acmeIssuer // we'll encode it later
			}

			if ap != nil {
				if ap.Issuer != nil {
					// encode issuer now that it's all set up
					issuerName := ap.Issuer.(caddy.Module).CaddyModule().ID.Name()
					ap.IssuerRaw = caddyconfig.JSONModuleObject(ap.Issuer, "module", issuerName, &warnings)
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

				// associate our new automation policy with this server block's hosts,
				// unless, of course, the server block has a key with no hosts, in which
				// case its automation policy becomes or blends with the default/global
				// automation policy because, of necessity, it applies to all hostnames
				// (i.e. it has no Subjects filter) -- in that case, we'll append it last
				if ap != catchAllAP {
					ap.Subjects = sblockHosts

					// if a combination of public and internal names were given
					// for this same server block and no issuer was specified, we
					// need to separate them out in the automation policies so
					// that the internal names can use the internal issuer and
					// the other names can use the default/public/ACME issuer
					var ap2 *caddytls.AutomationPolicy
					if ap.Issuer == nil {
						var internal, external []string
						for _, s := range ap.Subjects {
							if certmagic.SubjectQualifiesForPublicCert(s) {
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
							ap2.IssuerRaw = caddyconfig.JSONModuleObject(caddytls.InternalIssuer{}, "module", "internal", &warnings)
						}
					}
					if tlsApp.Automation == nil {
						tlsApp.Automation = new(caddytls.AutomationConfig)
					}
					tlsApp.Automation.Policies = append(tlsApp.Automation.Policies, ap)
					if ap2 != nil {
						tlsApp.Automation.Policies = append(tlsApp.Automation.Policies, ap2)
					}
				}
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

	// if any hostnames appear on the same server block as a key with
	// no host, they will not be used with route matchers because the
	// hostless key matches all hosts, therefore, it wouldn't be
	// considered for auto-HTTPS, so we need to make sure those hosts
	// are manually considered for managed certificates; we also need
	// to make sure that any of these names which are internal-only
	// get internal certificates by default rather than ACME
	var al caddytls.AutomateLoader
	internalAP := &caddytls.AutomationPolicy{
		IssuerRaw: json.RawMessage(`{"module":"internal"}`),
	}
	for h := range hostsSharedWithHostlessKey {
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

	// if there is a global/catch-all automation policy, ensure it goes last
	if catchAllAP != nil {
		// first, encode its issuer, if there is one
		if catchAllAP.Issuer != nil {
			issuerName := catchAllAP.Issuer.(caddy.Module).CaddyModule().ID.Name()
			catchAllAP.IssuerRaw = caddyconfig.JSONModuleObject(catchAllAP.Issuer, "module", issuerName, &warnings)
		}

		// then append it to the end of the policies list
		if tlsApp.Automation == nil {
			tlsApp.Automation = new(caddytls.AutomationConfig)
		}
		tlsApp.Automation.Policies = append(tlsApp.Automation.Policies, catchAllAP)
	}

	// do a little verification & cleanup
	if tlsApp.Automation != nil {
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
	}

	return tlsApp, warnings, nil
}

// newBaseAutomationPolicy returns a new TLS automation policy that gets
// its values from the global options map. It should be used as the base
// for any other automation policies. A nil policy (and no error) will be
// returned if there are no default/global options. However, if always is
// true, a non-nil value will always be returned (unless there is an error).
func newBaseAutomationPolicy(options map[string]interface{}, warnings []caddyconfig.Warning, always bool) (*caddytls.AutomationPolicy, error) {
	issuer, hasIssuer := options["cert_issuer"]

	acmeCA, hasACMECA := options["acme_ca"]
	acmeCARoot, hasACMECARoot := options["acme_ca_root"]
	acmeDNS, hasACMEDNS := options["acme_dns"]
	acmeEAB, hasACMEEAB := options["acme_eab"]

	email, hasEmail := options["email"]
	localCerts, hasLocalCerts := options["local_certs"]
	keyType, hasKeyType := options["key_type"]

	hasGlobalAutomationOpts := hasIssuer || hasACMECA || hasACMECARoot || hasACMEDNS || hasACMEEAB || hasEmail || hasLocalCerts || hasKeyType

	// if there are no global options related to automation policies
	// set, then we can just return right away
	if !hasGlobalAutomationOpts {
		if always {
			return new(caddytls.AutomationPolicy), nil
		}
		return nil, nil
	}

	ap := new(caddytls.AutomationPolicy)
	if keyType != nil {
		ap.KeyType = keyType.(string)
	}

	if hasIssuer {
		if hasACMECA || hasACMEDNS || hasACMEEAB || hasEmail || hasLocalCerts {
			return nil, fmt.Errorf("global options are ambiguous: cert_issuer is confusing when combined with acme_*, email, or local_certs options")
		}
		ap.Issuer = issuer.(certmagic.Issuer)
	} else if localCerts != nil {
		// internal issuer enabled trumps any ACME configurations; useful in testing
		ap.Issuer = new(caddytls.InternalIssuer) // we'll encode it later
	} else {
		if acmeCA == nil {
			acmeCA = ""
		}
		if email == nil {
			email = ""
		}
		mgr := &caddytls.ACMEIssuer{
			CA:    acmeCA.(string),
			Email: email.(string),
		}
		if acmeDNS != nil {
			provName := acmeDNS.(string)
			dnsProvModule, err := caddy.GetModule("dns.providers." + provName)
			if err != nil {
				return nil, fmt.Errorf("getting DNS provider module named '%s': %v", provName, err)
			}
			mgr.Challenges = &caddytls.ChallengesConfig{
				DNS: &caddytls.DNSChallengeConfig{
					ProviderRaw: caddyconfig.JSONModuleObject(dnsProvModule.New(), "name", provName, &warnings),
				},
			}
		}
		if acmeCARoot != nil {
			mgr.TrustedRootsPEMFiles = []string{acmeCARoot.(string)}
		}
		if acmeEAB != nil {
			mgr.ExternalAccount = acmeEAB.(*acme.EAB)
		}
		ap.Issuer = disambiguateACMEIssuer(mgr) // we'll encode it later
	}

	return ap, nil
}

// disambiguateACMEIssuer returns an issuer based on the properties of acmeIssuer.
// If acmeIssuer implicitly configures a certain kind of ACMEIssuer (for example,
// ZeroSSL), the proper wrapper over acmeIssuer will be returned instead.
func disambiguateACMEIssuer(acmeIssuer *caddytls.ACMEIssuer) certmagic.Issuer {
	// as a special case, we integrate with ZeroSSL's ACME endpoint if it looks like an
	// implicit ZeroSSL configuration (this requires a  wrapper type over ACMEIssuer
	// because of the EAB generation; if EAB is provided, we can use plain ACMEIssuer)
	if strings.Contains(acmeIssuer.CA, "acme.zerossl.com") && acmeIssuer.ExternalAccount == nil {
		return &caddytls.ZeroSSLIssuer{ACMEIssuer: acmeIssuer}
	}
	return acmeIssuer
}

// consolidateAutomationPolicies combines automation policies that are the same,
// for a cleaner overall output.
func consolidateAutomationPolicies(aps []*caddytls.AutomationPolicy) []*caddytls.AutomationPolicy {
	for i := 0; i < len(aps); i++ {
		for j := 0; j < len(aps); j++ {
			if j == i {
				continue
			}

			// if they're exactly equal in every way, just keep one of them
			if reflect.DeepEqual(aps[i], aps[j]) {
				aps = append(aps[:j], aps[j+1:]...)
				i--
				break
			}

			// if the policy is the same, we can keep just one, but we have
			// to be careful which one we keep; if only one has any hostnames
			// defined, then we need to keep the one without any hostnames,
			// otherwise the one without any subjects (a catch-all) would be
			// eaten up by the one with subjects; and if both have subjects, we
			// need to combine their lists
			if bytes.Equal(aps[i].IssuerRaw, aps[j].IssuerRaw) &&
				bytes.Equal(aps[i].StorageRaw, aps[j].StorageRaw) &&
				aps[i].MustStaple == aps[j].MustStaple &&
				aps[i].KeyType == aps[j].KeyType &&
				aps[i].OnDemand == aps[j].OnDemand &&
				aps[i].RenewalWindowRatio == aps[j].RenewalWindowRatio {
				if len(aps[i].Subjects) == 0 && len(aps[j].Subjects) > 0 {
					aps = append(aps[:j], aps[j+1:]...)
				} else if len(aps[i].Subjects) > 0 && len(aps[j].Subjects) == 0 {
					aps = append(aps[:i], aps[i+1:]...)
				} else {
					// avoid repeated subjects
					for _, subj := range aps[j].Subjects {
						if !sliceContains(aps[i].Subjects, subj) {
							aps[i].Subjects = append(aps[i].Subjects, subj)
						}
					}
					aps = append(aps[:j], aps[j+1:]...)
				}
				i--
				break
			}
		}
	}

	// ensure any catch-all policies go last
	sort.SliceStable(aps, func(i, j int) bool {
		return len(aps[i].Subjects) > len(aps[j].Subjects)
	})

	return aps
}
