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
	// If true, automatic HTTPS will be entirely disabled.
	Disabled bool `json:"disable,omitempty"`

	// If true, only automatic HTTP->HTTPS redirects will
	// be disabled.
	DisableRedir bool `json:"disable_redirects,omitempty"`

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
	// this map will store associations of HTTP listener
	// addresses to the routes that do HTTP->HTTPS redirects
	lnAddrRedirRoutes := make(map[string]Route)

	uniqueDomainsForCerts := make(map[string]struct{})

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
			continue
		}

		// skip if all listeners use the HTTP port
		if !srv.listenersUseAnyPortOtherThan(app.httpPort()) {
			app.logger.Info("server is listening only on the HTTP port, so no automatic HTTPS will be applied to this server",
				zap.String("server_name", srvName),
				zap.Int("http_port", app.httpPort()),
			)
			srv.AutoHTTPS.Disabled = true
			continue
		}

		defaultConnPolicies := caddytls.ConnectionPolicies{
			&caddytls.ConnectionPolicy{ALPN: defaultALPN},
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
			srv.TLSConnPolicies = defaultConnPolicies
		}

		// find all qualifying domain names (deduplicated) in this server
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

		// nothing more to do here if there are no
		// domains that qualify for automatic HTTPS
		if len(serverDomainSet) == 0 {
			continue
		}

		// for all the hostnames we found, filter them so we have
		// a deduplicated list of names for which to obtain certs
		for d := range serverDomainSet {
			if !srv.AutoHTTPS.Skipped(d, srv.AutoHTTPS.SkipCerts) {
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

		// tell the server to use TLS if it is not already doing so
		if srv.TLSConnPolicies == nil {
			srv.TLSConnPolicies = defaultConnPolicies
		}

		// nothing left to do if auto redirects are disabled
		if srv.AutoHTTPS.DisableRedir {
			continue
		}

		app.logger.Info("enabling automatic HTTP->HTTPS redirects",
			zap.String("server_name", srvName),
		)

		// create HTTP->HTTPS redirects
		for _, addr := range srv.Listen {
			netw, host, port, err := caddy.SplitNetworkAddress(addr)
			if err != nil {
				return fmt.Errorf("%s: invalid listener address: %v", srvName, addr)
			}

			if parts := strings.SplitN(port, "-", 2); len(parts) == 2 {
				port = parts[0]
			}
			redirTo := "https://{http.request.host}"

			if port != strconv.Itoa(app.httpsPort()) {
				redirTo += ":" + port
			}
			redirTo += "{http.request.uri}"

			// build the plaintext HTTP variant of this address
			httpRedirLnAddr := caddy.JoinNetworkAddress(netw, host, strconv.Itoa(app.httpPort()))

			// build the matcher set for this redirect route
			// (note that we happen to bypass Provision and
			// Validate steps for these matcher modules)
			matcherSet := MatcherSet{MatchProtocol("http")}
			if len(srv.AutoHTTPS.Skip) > 0 {
				matcherSet = append(matcherSet, MatchNegate{
					Matchers: MatcherSet{MatchHost(srv.AutoHTTPS.Skip)},
				})
			}

			// create the route that does the redirect and associate
			// it with the listener address it will be served from
			// (note that we happen to bypass any Provision or Validate
			// steps on the handler modules created here)
			lnAddrRedirRoutes[httpRedirLnAddr] = Route{
				MatcherSets: []MatcherSet{matcherSet},
				Handlers: []MiddlewareHandler{
					StaticResponse{
						StatusCode: WeakString(strconv.Itoa(http.StatusPermanentRedirect)),
						Headers: http.Header{
							"Location":   []string{redirTo},
							"Connection": []string{"close"},
						},
						Close: true,
					},
				},
			}
		}
	}

	// we now have a list of all the unique names for which we need certs;
	// turn the set into a slice so that phase 2 can use it
	app.allCertDomains = make([]string, 0, len(uniqueDomainsForCerts))
	var internal, external []string
	for d := range uniqueDomainsForCerts {
		if certmagic.SubjectQualifiesForPublicCert(d) {
			external = append(external, d)
		} else {
			internal = append(internal, d)
		}
		app.allCertDomains = append(app.allCertDomains, d)
	}

	// ensure there is an automation policy to handle these certs
	err := app.createAutomationPolicies(ctx, external, internal)
	if err != nil {
		return err
	}

	// if there are HTTP->HTTPS redirects to add, do so now
	if len(lnAddrRedirRoutes) == 0 {
		return nil
	}

	var redirServerAddrs []string
	var redirRoutes RouteList

	// for each redirect listener, see if there's already a
	// server configured to listen on that exact address; if so,
	// simply add the redirect route to the end of its route
	// list; otherwise, we'll create a new server for all the
	// listener addresses that are unused and serve the
	// remaining redirects from it
redirRoutesLoop:
	for addr, redirRoute := range lnAddrRedirRoutes {
		for srvName, srv := range app.Servers {
			if srv.hasListenerAddress(addr) {
				// user has configured a server for the same address
				// that the redirect runs from; simply append our
				// redirect route to the existing routes, with a
				// caveat that their config might override ours
				app.logger.Warn("server is listening on same interface as redirects, so automatic HTTP->HTTPS redirects might be overridden by your own configuration",
					zap.String("server_name", srvName),
					zap.String("interface", addr),
				)
				srv.Routes = append(srv.Routes, redirRoute)
				continue redirRoutesLoop
			}
		}
		// no server with this listener address exists;
		// save this address and route for custom server
		redirServerAddrs = append(redirServerAddrs, addr)
		redirRoutes = append(redirRoutes, redirRoute)
	}

	// if there are routes remaining which do not belong
	// in any existing server, make our own to serve the
	// rest of the redirects
	if len(redirServerAddrs) > 0 {
		app.Servers["remaining_auto_https_redirects"] = &Server{
			Listen: redirServerAddrs,
			Routes: redirRoutes,
		}
	}

	return nil
}

// createAutomationPolicy ensures that automated certificates for this
// app are managed properly. This adds up to two automation policies:
// one for the public names, and one for the internal names. If a catch-all
// automation policy exists, it will be shallow-copied and used as the
// base for the new ones (this is important for preserving behavior the
// user intends to be "defaults").
func (app *App) createAutomationPolicies(ctx caddy.Context, publicNames, internalNames []string) error {
	// nothing to do if no names to manage certs for
	if len(publicNames) == 0 && len(internalNames) == 0 {
		return nil
	}

	// start by finding a base policy that the user may have defined
	// which should, in theory, apply to any policies derived from it;
	// typically this would be a "catch-all" policy with no host filter
	var matchingPolicy *caddytls.AutomationPolicy
	if app.tlsApp.Automation != nil {
		// if an existing policy matches (specifically, a catch-all policy),
		// we should inherit from it, because that is what the user expects;
		// this is very common for user setting a default issuer, with a
		// custom CA endpoint, for example - whichever one we choose must
		// have a host list that is a superset of the policy we make...
		// the policy with no host filter is guaranteed to qualify
		for _, ap := range app.tlsApp.Automation.Policies {
			if len(ap.Hosts) == 0 {
				matchingPolicy = ap
				break
			}
		}
	}
	if matchingPolicy == nil {
		matchingPolicy = new(caddytls.AutomationPolicy)
	}

	// addPolicy adds an automation policy that uses issuer for hosts.
	addPolicy := func(issuer certmagic.Issuer, hosts []string) error {
		// shallow-copy the matching policy; we want to inherit
		// from it, not replace it... this takes two lines to
		// overrule compiler optimizations
		policyCopy := *matchingPolicy
		newPolicy := &policyCopy

		// very important to provision it, since we are
		// bypassing the JSON-unmarshaling step
		if prov, ok := issuer.(caddy.Provisioner); ok {
			err := prov.Provision(ctx)
			if err != nil {
				return err
			}
		}
		newPolicy.Issuer = issuer
		newPolicy.Hosts = hosts

		return app.tlsApp.AddAutomationPolicy(newPolicy)
	}

	if len(publicNames) > 0 {
		var acmeIssuer *caddytls.ACMEIssuer
		// if it has an ACME issuer, maybe we can just use that
		// TODO: we might need a deep copy here, like a Clone() method on ACMEIssuer...
		acmeIssuer, _ = matchingPolicy.Issuer.(*caddytls.ACMEIssuer)
		if acmeIssuer == nil {
			acmeIssuer = new(caddytls.ACMEIssuer)
		}
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
		if err := addPolicy(acmeIssuer, publicNames); err != nil {
			return err
		}
	}

	if len(internalNames) > 0 {
		internalIssuer := new(caddytls.InternalIssuer)
		if err := addPolicy(internalIssuer, internalNames); err != nil {
			return err
		}
	}

	err := app.tlsApp.Validate()
	if err != nil {
		return err
	}

	return nil
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
