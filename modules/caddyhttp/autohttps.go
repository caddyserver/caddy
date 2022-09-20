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

package caddyhttp

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

// AutoHTTPSConfig is used to disable automatic HTTPS
// or certain aspects of it for a specific server.
// HTTPS is enabled automatically and by default when
// qualifying hostnames are available from the config.
type AutoHTTPSConfig struct {
	// If true, automatic HTTPS will be entirely disabled,
	// including certificate management and redirects.
	Disabled bool `json:"disable,omitempty"`

	// If true, only automatic HTTP->HTTPS redirects will
	// be disabled, but other auto-HTTPS features will
	// remain enabled.
	DisableRedir bool `json:"disable_redirects,omitempty"`

	// If true, automatic certificate management will be
	// disabled, but other auto-HTTPS features will
	// remain enabled.
	DisableCerts bool `json:"disable_certificates,omitempty"`

	// Hosts/domain names listed here will not be included
	// in automatic HTTPS (they will not have certificates
	// loaded nor redirects applied).
	Skip []string `json:"skip,omitempty"`

	// Hosts/domain names listed here will still be enabled
	// for automatic HTTPS (unless in the Skip list), except
	// that certificates will not be provisioned and managed
	// for these names.
	SkipCerts []string `json:"skip_certificates,omitempty"`

	// By default, automatic HTTPS will obtain and renew
	// certificates for qualifying hostnames. However, if
	// a certificate with a matching SAN is already loaded
	// into the cache, certificate management will not be
	// enabled. To force automated certificate management
	// regardless of loaded certificates, set this to true.
	IgnoreLoadedCerts bool `json:"ignore_loaded_certificates,omitempty"`
}

// Skipped returns true if name is in skipSlice, which
// should be either the Skip or SkipCerts field on ahc.
func (ahc AutoHTTPSConfig) Skipped(name string, skipSlice []string) bool {
	for _, n := range skipSlice {
		if name == n {
			return true
		}
	}
	return false
}

// automaticHTTPSPhase1 provisions all route matchers, determines
// which domain names found in the routes qualify for automatic
// HTTPS, and sets up HTTP->HTTPS redirects. This phase must occur
// at the beginning of provisioning, because it may add routes and
// even servers to the app, which still need to be set up with the
// rest of them during provisioning.
func (app *App) automaticHTTPSPhase1(ctx caddy.Context, repl *caddy.Replacer) error {
	// this map acts as a set to store the domain names
	// for which we will manage certificates automatically
	uniqueDomainsForCerts := make(map[string]struct{})

	// this maps domain names for automatic HTTP->HTTPS
	// redirects to their destination server addresses
	// (there might be more than 1 if bind is used; see
	// https://github.com/caddyserver/caddy/issues/3443)
	redirDomains := make(map[string][]caddy.NetworkAddress)

	// the log configuration for an HTTPS enabled server
	var logCfg *ServerLogConfig

	for srvName, srv := range app.Servers {
		// as a prerequisite, provision route matchers; this is
		// required for all routes on all servers, and must be
		// done before we attempt to do phase 1 of auto HTTPS,
		// since we have to access the decoded host matchers the
		// handlers will be provisioned later
		if srv.Routes != nil {
			err := srv.Routes.ProvisionMatchers(ctx)
			if err != nil {
				return fmt.Errorf("server %s: setting up route matchers: %v", srvName, err)
			}
		}

		// prepare for automatic HTTPS
		if srv.AutoHTTPS == nil {
			srv.AutoHTTPS = new(AutoHTTPSConfig)
		}
		if srv.AutoHTTPS.Disabled {
			app.logger.Warn("automatic HTTPS is completely disabled for server", zap.String("server_name", srvName))
			continue
		}

		// skip if all listeners use the HTTP port
		if !srv.listenersUseAnyPortOtherThan(app.httpPort()) {
			app.logger.Warn("server is listening only on the HTTP port, so no automatic HTTPS will be applied to this server",
				zap.String("server_name", srvName),
				zap.Int("http_port", app.httpPort()),
			)
			srv.AutoHTTPS.Disabled = true
			continue
		}

		// if all listeners are on the HTTPS port, make sure
		// there is at least one TLS connection policy; it
		// should be obvious that they want to use TLS without
		// needing to specify one empty policy to enable it
		if srv.TLSConnPolicies == nil &&
			!srv.listenersUseAnyPortOtherThan(app.httpsPort()) {
			app.logger.Info("server is listening only on the HTTPS port but has no TLS connection policies; adding one to enable TLS",
				zap.String("server_name", srvName),
				zap.Int("https_port", app.httpsPort()),
			)
			srv.TLSConnPolicies = caddytls.ConnectionPolicies{new(caddytls.ConnectionPolicy)}
		}

		// find all qualifying domain names (deduplicated) in this server
		// (this is where we need the provisioned, decoded request matchers)
		serverDomainSet := make(map[string]struct{})
		for routeIdx, route := range srv.Routes {
			for matcherSetIdx, matcherSet := range route.MatcherSets {
				for matcherIdx, m := range matcherSet {
					if hm, ok := m.(*MatchHost); ok {
						for hostMatcherIdx, d := range *hm {
							var err error
							d, err = repl.ReplaceOrErr(d, true, false)
							if err != nil {
								return fmt.Errorf("%s: route %d, matcher set %d, matcher %d, host matcher %d: %v",
									srvName, routeIdx, matcherSetIdx, matcherIdx, hostMatcherIdx, err)
							}
							if !srv.AutoHTTPS.Skipped(d, srv.AutoHTTPS.Skip) {
								serverDomainSet[d] = struct{}{}
							}
						}
					}
				}
			}
		}

		// nothing more to do here if there are no domains that qualify for
		// automatic HTTPS and there are no explicit TLS connection policies:
		// if there is at least one domain but no TLS conn policy (F&&T), we'll
		// add one below; if there are no domains but at least one TLS conn
		// policy (meaning TLS is enabled) (T&&F), it could be a catch-all with
		// on-demand TLS -- and in that case we would still need HTTP->HTTPS
		// redirects, which we set up below; hence these two conditions
		if len(serverDomainSet) == 0 && len(srv.TLSConnPolicies) == 0 {
			continue
		}

		// clone the logger so we can apply it to the HTTP server
		// (not sure if necessary to clone it; but probably safer)
		// (we choose one log cfg arbitrarily; not sure which is best)
		if srv.Logs != nil {
			logCfg = srv.Logs.clone()
		}

		// for all the hostnames we found, filter them so we have
		// a deduplicated list of names for which to obtain certs
		// (only if cert management not disabled for this server)
		if srv.AutoHTTPS.DisableCerts {
			app.logger.Warn("skipping automated certificate management for server because it is disabled", zap.String("server_name", srvName))
		} else {
			for d := range serverDomainSet {
				// the implicit Tailscale manager module will get its own certs at run-time
				if isTailscaleDomain(d) {
					continue
				}

				if certmagic.SubjectQualifiesForCert(d) &&
					!srv.AutoHTTPS.Skipped(d, srv.AutoHTTPS.SkipCerts) {
					// if a certificate for this name is already loaded,
					// don't obtain another one for it, unless we are
					// supposed to ignore loaded certificates
					if !srv.AutoHTTPS.IgnoreLoadedCerts &&
						len(app.tlsApp.AllMatchingCertificates(d)) > 0 {
						app.logger.Info("skipping automatic certificate management because one or more matching certificates are already loaded",
							zap.String("domain", d),
							zap.String("server_name", srvName),
						)
						continue
					}

					// most clients don't accept wildcards like *.tld... we
					// can handle that, but as a courtesy, warn the user
					if strings.Contains(d, "*") &&
						strings.Count(strings.Trim(d, "."), ".") == 1 {
						app.logger.Warn("most clients do not trust second-level wildcard certificates (*.tld)",
							zap.String("domain", d))
					}

					uniqueDomainsForCerts[d] = struct{}{}
				}
			}
		}

		// tell the server to use TLS if it is not already doing so
		if srv.TLSConnPolicies == nil {
			srv.TLSConnPolicies = caddytls.ConnectionPolicies{new(caddytls.ConnectionPolicy)}
		}

		// nothing left to do if auto redirects are disabled
		if srv.AutoHTTPS.DisableRedir {
			app.logger.Warn("automatic HTTP->HTTPS redirects are disabled", zap.String("server_name", srvName))
			continue
		}

		app.logger.Info("enabling automatic HTTP->HTTPS redirects", zap.String("server_name", srvName))

		// create HTTP->HTTPS redirects
		for _, listenAddr := range srv.Listen {
			// figure out the address we will redirect to...
			addr, err := caddy.ParseNetworkAddress(listenAddr)
			if err != nil {
				msg := "%s: invalid listener address: %v"
				if strings.Count(listenAddr, ":") > 1 {
					msg = msg + ", there are too many colons, so the port is ambiguous. Did you mean to wrap the IPv6 address with [] brackets?"
				}
				return fmt.Errorf(msg, srvName, listenAddr)
			}

			// this address might not have a hostname, i.e. might be a
			// catch-all address for a particular port; we need to keep
			// track if it is, so we can set up redirects for it anyway
			// (e.g. the user might have enabled on-demand TLS); we use
			// an empty string to indicate a catch-all, which we have to
			// treat special later
			if len(serverDomainSet) == 0 {
				redirDomains[""] = append(redirDomains[""], addr)
				continue
			}

			// ...and associate it with each domain in this server
			for d := range serverDomainSet {
				// if this domain is used on more than one HTTPS-enabled
				// port, we'll have to choose one, so prefer the HTTPS port
				if _, ok := redirDomains[d]; !ok ||
					addr.StartPort == uint(app.httpsPort()) {
					redirDomains[d] = []caddy.NetworkAddress{addr}
				}
			}
		}
	}

	// we now have a list of all the unique names for which we need certs;
	// turn the set into a slice so that phase 2 can use it
	app.allCertDomains = make([]string, 0, len(uniqueDomainsForCerts))
	var internal []string
uniqueDomainsLoop:
	for d := range uniqueDomainsForCerts {
		// whether or not there is already an automation policy for this
		// name, we should add it to the list to manage a cert for it
		app.allCertDomains = append(app.allCertDomains, d)

		// some names we've found might already have automation policies
		// explicitly specified for them; we should exclude those from
		// our hidden/implicit policy, since applying a name to more than
		// one automation policy would be confusing and an error
		if app.tlsApp.Automation != nil {
			for _, ap := range app.tlsApp.Automation.Policies {
				for _, apHost := range ap.Subjects {
					if apHost == d {
						continue uniqueDomainsLoop
					}
				}
			}
		}

		// if no automation policy exists for the name yet, we
		// will associate it with an implicit one
		if !certmagic.SubjectQualifiesForPublicCert(d) {
			internal = append(internal, d)
		}
	}

	// ensure there is an automation policy to handle these certs
	err := app.createAutomationPolicies(ctx, internal)
	if err != nil {
		return err
	}

	// we need to reduce the mapping, i.e. group domains by address
	// since new routes are appended to servers by their address
	domainsByAddr := make(map[string][]string)
	for domain, addrs := range redirDomains {
		for _, addr := range addrs {
			addrStr := addr.String()
			domainsByAddr[addrStr] = append(domainsByAddr[addrStr], domain)
		}
	}

	// these keep track of the redirect server address(es)
	// and the routes for those servers which actually
	// respond with the redirects
	redirServerAddrs := make(map[string]struct{})
	redirServers := make(map[string][]Route)
	var redirRoutes RouteList

	for addrStr, domains := range domainsByAddr {
		// build the matcher set for this redirect route; (note that we happen
		// to bypass Provision and Validate steps for these matcher modules)
		matcherSet := MatcherSet{MatchProtocol("http")}
		// match on known domain names, unless it's our special case of a
		// catch-all which is an empty string (common among catch-all sites
		// that enable on-demand TLS for yet-unknown domain names)
		if !(len(domains) == 1 && domains[0] == "") {
			matcherSet = append(matcherSet, MatchHost(domains))
		}

		addr, err := caddy.ParseNetworkAddress(addrStr)
		if err != nil {
			return err
		}
		redirRoute := app.makeRedirRoute(addr.StartPort, matcherSet)

		// use the network/host information from the address,
		// but change the port to the HTTP port then rebuild
		redirAddr := addr
		redirAddr.StartPort = uint(app.httpPort())
		redirAddr.EndPort = redirAddr.StartPort
		redirAddrStr := redirAddr.String()

		redirServers[redirAddrStr] = append(redirServers[redirAddrStr], redirRoute)
	}

	// on-demand TLS means that hostnames may be used which are not
	// explicitly defined in the config, and we still need to redirect
	// those; so we can append a single catch-all route (notice there
	// is no Host matcher) after the other redirect routes which will
	// allow us to handle unexpected/new hostnames... however, it's
	// not entirely clear what the redirect destination should be,
	// so I'm going to just hard-code the app's HTTPS port and call
	// it good for now...
	// TODO: This implies that all plaintext requests will be blindly
	// redirected to their HTTPS equivalent, even if this server
	// doesn't handle that hostname at all; I don't think this is a
	// bad thing, and it also obscures the actual hostnames that this
	// server is configured to match on, which may be desirable, but
	// it's not something that should be relied on. We can change this
	// if we want to.
	appendCatchAll := func(routes []Route) []Route {
		return append(routes, app.makeRedirRoute(uint(app.httpsPort()), MatcherSet{MatchProtocol("http")}))
	}

redirServersLoop:
	for redirServerAddr, routes := range redirServers {
		// for each redirect listener, see if there's already a
		// server configured to listen on that exact address; if so,
		// insert the redirect route to the end of its route list
		// after any other routes with host matchers; otherwise,
		// we'll create a new server for all the listener addresses
		// that are unused and serve the remaining redirects from it
		for _, srv := range app.Servers {
			// only look at servers which listen on an address which
			// we want to add redirects to
			if !srv.hasListenerAddress(redirServerAddr) {
				continue
			}

			// find the index of the route after the last route with a host
			// matcher, then insert the redirects there, but before any
			// user-defined catch-all routes
			// see https://github.com/caddyserver/caddy/issues/3212
			insertIndex := srv.findLastRouteWithHostMatcher()

			// add the redirects at the insert index, except for when
			// we have a catch-all for HTTPS, in which case the user's
			// defined catch-all should take precedence. See #4829
			if len(uniqueDomainsForCerts) != 0 {
				srv.Routes = append(srv.Routes[:insertIndex], append(routes, srv.Routes[insertIndex:]...)...)
			}

			// append our catch-all route in case the user didn't define their own
			srv.Routes = appendCatchAll(srv.Routes)

			continue redirServersLoop
		}

		// no server with this listener address exists;
		// save this address and route for custom server
		redirServerAddrs[redirServerAddr] = struct{}{}
		redirRoutes = append(redirRoutes, routes...)
	}

	// if there are routes remaining which do not belong
	// in any existing server, make our own to serve the
	// rest of the redirects
	if len(redirServerAddrs) > 0 {
		redirServerAddrsList := make([]string, 0, len(redirServerAddrs))
		for a := range redirServerAddrs {
			redirServerAddrsList = append(redirServerAddrsList, a)
		}
		app.Servers["remaining_auto_https_redirects"] = &Server{
			Listen: redirServerAddrsList,
			Routes: appendCatchAll(redirRoutes),
			Logs:   logCfg,
		}
	}

	return nil
}

func (app *App) makeRedirRoute(redirToPort uint, matcherSet MatcherSet) Route {
	redirTo := "https://{http.request.host}"

	// since this is an external redirect, we should only append an explicit
	// port if we know it is not the officially standardized HTTPS port, and,
	// notably, also not the port that Caddy thinks is the HTTPS port (the
	// configurable HTTPSPort parameter) - we can't change the standard HTTPS
	// port externally, so that config parameter is for internal use only;
	// we also do not append the port if it happens to be the HTTP port as
	// well, obviously (for example, user defines the HTTP port explicitly
	// in the list of listen addresses for a server)
	if redirToPort != uint(app.httpPort()) &&
		redirToPort != uint(app.httpsPort()) &&
		redirToPort != DefaultHTTPPort &&
		redirToPort != DefaultHTTPSPort {
		redirTo += ":" + strconv.Itoa(int(redirToPort))
	}

	redirTo += "{http.request.uri}"
	return Route{
		MatcherSets: []MatcherSet{matcherSet},
		Handlers: []MiddlewareHandler{
			StaticResponse{
				StatusCode: WeakString(strconv.Itoa(http.StatusPermanentRedirect)),
				Headers: http.Header{
					"Location": []string{redirTo},
				},
				Close: true,
			},
		},
	}
}

// createAutomationPolicies ensures that automated certificates for this
// app are managed properly. This adds up to two automation policies:
// one for the public names, and one for the internal names. If a catch-all
// automation policy exists, it will be shallow-copied and used as the
// base for the new ones (this is important for preserving behavior the
// user intends to be "defaults").
func (app *App) createAutomationPolicies(ctx caddy.Context, internalNames []string) error {
	// before we begin, loop through the existing automation policies
	// and, for any ACMEIssuers we find, make sure they're filled in
	// with default values that might be specified in our HTTP app; also
	// look for a base (or "catch-all" / default) automation policy,
	// which we're going to essentially require, to make sure it has
	// those defaults, too
	var basePolicy *caddytls.AutomationPolicy
	var foundBasePolicy bool
	if app.tlsApp.Automation == nil {
		// we will expect this to not be nil from now on
		app.tlsApp.Automation = new(caddytls.AutomationConfig)
	}
	for _, ap := range app.tlsApp.Automation.Policies {
		// set up default issuer -- honestly, this is only
		// really necessary because the HTTP app is opinionated
		// and has settings which could be inferred as new
		// defaults for the ACMEIssuer in the TLS app (such as
		// what the HTTP and HTTPS ports are)
		if ap.Issuers == nil {
			var err error
			ap.Issuers, err = caddytls.DefaultIssuersProvisioned(ctx)
			if err != nil {
				return err
			}
		}
		for _, iss := range ap.Issuers {
			if acmeIssuer, ok := iss.(acmeCapable); ok {
				err := app.fillInACMEIssuer(acmeIssuer.GetACMEIssuer())
				if err != nil {
					return err
				}
			}
		}

		// if no external managers were configured, enable
		// implicit Tailscale support for convenience
		if ap.Managers == nil {
			ts, err := implicitTailscale(ctx)
			if err != nil {
				return err
			}
			ap.Managers = []certmagic.Manager{ts}

			// must reprovision the automation policy so that the underlying
			// CertMagic config knows about the updated Managers
			if err := ap.Provision(app.tlsApp); err != nil {
				return fmt.Errorf("re-provisioning automation policy: %v", err)
			}
		}

		// while we're here, is this the catch-all/base policy?
		if !foundBasePolicy && len(ap.Subjects) == 0 {
			basePolicy = ap
			foundBasePolicy = true
		}
	}

	if basePolicy == nil {
		// no base policy found; we will make one
		basePolicy = new(caddytls.AutomationPolicy)
	}

	if basePolicy.Managers == nil {
		// add implicit Tailscale integration, for harmless convenience
		ts, err := implicitTailscale(ctx)
		if err != nil {
			return err
		}
		basePolicy.Managers = []certmagic.Manager{ts}
	}

	// if the basePolicy has an existing ACMEIssuer (particularly to
	// include any type that embeds/wraps an ACMEIssuer), let's use it
	// (I guess we just use the first one?), otherwise we'll make one
	var baseACMEIssuer *caddytls.ACMEIssuer
	for _, iss := range basePolicy.Issuers {
		if acmeWrapper, ok := iss.(acmeCapable); ok {
			baseACMEIssuer = acmeWrapper.GetACMEIssuer()
			break
		}
	}
	if baseACMEIssuer == nil {
		// note that this happens if basePolicy.Issuers is empty
		// OR if it is not empty but does not have not an ACMEIssuer
		baseACMEIssuer = new(caddytls.ACMEIssuer)
	}

	// if there was a base policy to begin with, we already
	// filled in its issuer's defaults; if there wasn't, we
	// still need to do that
	if !foundBasePolicy {
		err := app.fillInACMEIssuer(baseACMEIssuer)
		if err != nil {
			return err
		}
	}

	// never overwrite any other issuer that might already be configured
	if basePolicy.Issuers == nil {
		var err error
		basePolicy.Issuers, err = caddytls.DefaultIssuersProvisioned(ctx)
		if err != nil {
			return err
		}
		for _, iss := range basePolicy.Issuers {
			if acmeIssuer, ok := iss.(acmeCapable); ok {
				err := app.fillInACMEIssuer(acmeIssuer.GetACMEIssuer())
				if err != nil {
					return err
				}
			}
		}
	}

	if !foundBasePolicy {
		// there was no base policy to begin with, so add
		// our base/catch-all policy - this will serve the
		// public-looking names as well as any other names
		// that don't match any other policy
		err := app.tlsApp.AddAutomationPolicy(basePolicy)
		if err != nil {
			return err
		}
	} else {
		// a base policy already existed; we might have
		// changed it, so re-provision it
		err := basePolicy.Provision(app.tlsApp)
		if err != nil {
			return err
		}
	}

	// public names will be taken care of by the base (catch-all)
	// policy, which we've ensured exists if not already specified;
	// internal names, however, need to be handled by an internal
	// issuer, which we need to make a new policy for, scoped to
	// just those names (yes, this logic is a bit asymmetric, but
	// it works, because our assumed/natural default issuer is an
	// ACME issuer)
	if len(internalNames) > 0 {
		internalIssuer := new(caddytls.InternalIssuer)

		// shallow-copy the base policy; we want to inherit
		// from it, not replace it... this takes two lines to
		// overrule compiler optimizations
		policyCopy := *basePolicy
		newPolicy := &policyCopy

		// very important to provision the issuer, since we
		// are bypassing the JSON-unmarshaling step
		if err := internalIssuer.Provision(ctx); err != nil {
			return err
		}

		// this policy should apply only to the given names
		// and should use our issuer -- yes, this overrides
		// any issuer that may have been set in the base
		// policy, but we do this because these names do not
		// already have a policy associated with them, which
		// is easy to do; consider the case of a Caddyfile
		// that has only "localhost" as a name, but sets the
		// default/global ACME CA to the Let's Encrypt staging
		// endpoint... they probably don't intend to change the
		// fundamental set of names that setting applies to,
		// rather they just want to change the CA for the set
		// of names that would normally use the production API;
		// anyway, that gets into the weeds a bit...
		newPolicy.Subjects = internalNames
		newPolicy.Issuers = []certmagic.Issuer{internalIssuer}
		err := app.tlsApp.AddAutomationPolicy(newPolicy)
		if err != nil {
			return err
		}
	}

	// we just changed a lot of stuff, so double-check that it's all good
	err := app.tlsApp.Validate()
	if err != nil {
		return err
	}

	return nil
}

// fillInACMEIssuer fills in default values into acmeIssuer that
// are defined in app; these values at time of writing are just
// app.HTTPPort and app.HTTPSPort, which are used by ACMEIssuer.
// Sure, we could just use the global/CertMagic defaults, but if
// a user has configured those ports in the HTTP app, it makes
// sense to use them in the TLS app too, even if they forgot (or
// were too lazy, like me) to set it in each automation policy
// that uses it -- this just makes things a little less tedious
// for the user, so they don't have to repeat those ports in
// potentially many places. This function never steps on existing
// config values. If any changes are made, acmeIssuer is
// reprovisioned. acmeIssuer must not be nil.
func (app *App) fillInACMEIssuer(acmeIssuer *caddytls.ACMEIssuer) error {
	if app.HTTPPort > 0 || app.HTTPSPort > 0 {
		if acmeIssuer.Challenges == nil {
			acmeIssuer.Challenges = new(caddytls.ChallengesConfig)
		}
	}
	if app.HTTPPort > 0 {
		if acmeIssuer.Challenges.HTTP == nil {
			acmeIssuer.Challenges.HTTP = new(caddytls.HTTPChallengeConfig)
		}
		// don't overwrite existing explicit config
		if acmeIssuer.Challenges.HTTP.AlternatePort == 0 {
			acmeIssuer.Challenges.HTTP.AlternatePort = app.HTTPPort
		}
	}
	if app.HTTPSPort > 0 {
		if acmeIssuer.Challenges.TLSALPN == nil {
			acmeIssuer.Challenges.TLSALPN = new(caddytls.TLSALPNChallengeConfig)
		}
		// don't overwrite existing explicit config
		if acmeIssuer.Challenges.TLSALPN.AlternatePort == 0 {
			acmeIssuer.Challenges.TLSALPN.AlternatePort = app.HTTPSPort
		}
	}
	// we must provision all ACME issuers, even if nothing
	// was changed, because we don't know if they are new
	// and haven't been provisioned yet; if an ACME issuer
	// never gets provisioned, its Agree field stays false,
	// which leads to, um, problems later on
	return acmeIssuer.Provision(app.ctx)
}

// automaticHTTPSPhase2 begins certificate management for
// all names in the qualifying domain set for each server.
// This phase must occur after provisioning and at the end
// of app start, after all the servers have been started.
// Doing this last ensures that there won't be any race
// for listeners on the HTTP or HTTPS ports when management
// is async (if CertMagic's solvers bind to those ports
// first, then our servers would fail to bind to them,
// which would be bad, since CertMagic's bindings are
// temporary and don't serve the user's sites!).
func (app *App) automaticHTTPSPhase2() error {
	if len(app.allCertDomains) == 0 {
		return nil
	}
	app.logger.Info("enabling automatic TLS certificate management",
		zap.Strings("domains", app.allCertDomains),
	)
	err := app.tlsApp.Manage(app.allCertDomains)
	if err != nil {
		return fmt.Errorf("managing certificates for %v: %s", app.allCertDomains, err)
	}
	app.allCertDomains = nil // no longer needed; allow GC to deallocate
	return nil
}

// implicitTailscale returns a new and provisioned Tailscale module configured to be optional.
func implicitTailscale(ctx caddy.Context) (caddytls.Tailscale, error) {
	ts := caddytls.Tailscale{Optional: true}
	err := ts.Provision(ctx)
	return ts, err
}

func isTailscaleDomain(name string) bool {
	return strings.HasSuffix(strings.ToLower(name), ".ts.net")
}

type acmeCapable interface{ GetACMEIssuer() *caddytls.ACMEIssuer }
