package caddyhttp

import (
	"fmt"
	"net/http"
	"strconv"

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
	// this map acts as a set to store the domain names
	// for which we will manage certificates automatically
	uniqueDomainsForCerts := make(map[string]struct{})

	// this maps domain names for automatic HTTP->HTTPS
	// redirects to their destination server address
	redirDomains := make(map[string]caddy.ParsedAddress)

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
							if certmagic.HostQualifies(d) &&
								!srv.AutoHTTPS.Skipped(d, srv.AutoHTTPS.Skip) {
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
			// figure out the address we will redirect to...
			addr, err := caddy.ParseNetworkAddress(addr)
			if err != nil {
				return fmt.Errorf("%s: invalid listener address: %v", srvName, addr)
			}

			// ...and associate it with each domain in this server
			for d := range serverDomainSet {
				// if this domain is used on more than one HTTPS-enabled
				// port, we'll have to choose one, so prefer the HTTPS port
				if _, ok := redirDomains[d]; !ok ||
					addr.StartPort == uint(app.httpsPort()) {
					redirDomains[d] = addr
				}
			}
		}
	}

	// we now have a list of all the unique names for which we need certs;
	// turn the set into a slice so that phase 2 can use it
	app.allCertDomains = make([]string, 0, len(uniqueDomainsForCerts))
	for d := range uniqueDomainsForCerts {
		app.allCertDomains = append(app.allCertDomains, d)
	}

	// ensure there is an automation policy to handle these certs
	err := app.createAutomationPolicy(ctx)
	if err != nil {
		return err
	}

	// we're done if there are no HTTP->HTTPS redirects to add
	if len(redirDomains) == 0 {
		return nil
	}

	// we need to reduce the mapping, i.e. group domains by address
	// since new routes are appended to servers by their address
	domainsByAddr := make(map[string][]string)
	for domain, addr := range redirDomains {
		addrStr := addr.String()
		domainsByAddr[addrStr] = append(domainsByAddr[addrStr], domain)
	}

	// these keep track of the redirect server address(es)
	// and the routes for those servers which actually
	// respond with the redirects
	redirServerAddrs := make(map[string]struct{})
	var redirRoutes RouteList

	redirServers := make(map[string][]Route)

	for addrStr, domains := range domainsByAddr {
		// build the matcher set for this redirect route
		// (note that we happen to bypass Provision and
		// Validate steps for these matcher modules)
		matcherSet := MatcherSet{
			MatchProtocol("http"),
			MatchHost(domains),
		}

		// build the address to which to redirect
		addr, err := caddy.ParseNetworkAddress(addrStr)
		if err != nil {
			return err
		}
		redirTo := "https://{http.request.host}"
		if addr.StartPort != DefaultHTTPSPort {
			redirTo += ":" + strconv.Itoa(int(addr.StartPort))
		}
		redirTo += "{http.request.uri}"

		// build the route
		redirRoute := Route{
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
	appendCatchAll := func(routes []Route) []Route {
		redirTo := "https://{http.request.host}"
		if app.httpsPort() != DefaultHTTPSPort {
			redirTo += ":" + strconv.Itoa(app.httpsPort())
		}
		redirTo += "{http.request.uri}"
		routes = append(routes, Route{
			MatcherSets: []MatcherSet{MatcherSet{MatchProtocol("http")}},
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
		})
		return routes
	}

redirServersLoop:
	for redirServerAddr, routes := range redirServers {
		// for each redirect listener, see if there's already a
		// server configured to listen on that exact address; if so,
		// simply add the redirect route to the end of its route
		// list; otherwise, we'll create a new server for all the
		// listener addresses that are unused and serve the
		// remaining redirects from it
		for srvName, srv := range app.Servers {
			if srv.hasListenerAddress(redirServerAddr) {
				// user has configured a server for the same address
				// that the redirect runs from; simply append our
				// redirect route to the existing routes, with a
				// caveat that their config might override ours
				app.logger.Warn("user server is listening on same interface as automatic HTTP->HTTPS redirects; user-configured routes might override these redirects",
					zap.String("server_name", srvName),
					zap.String("interface", redirServerAddr),
				)
				srv.Routes = append(srv.Routes, appendCatchAll(routes)...)
				continue redirServersLoop
			}
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
		}
	}

	return nil
}

// createAutomationPolicy ensures that certificates for this app are
// managed properly; for example, it's implied that the HTTPPort
// should also be the port the HTTP challenge is solved on; the same
// for HTTPS port and TLS-ALPN challenge also. We need to tell the
// TLS app to manage these certs by honoring those port configurations,
// so we either find an existing matching automation policy with an
// ACME issuer, or make a new one and append it.
func (app *App) createAutomationPolicy(ctx caddy.Context) error {
	var matchingPolicy *caddytls.AutomationPolicy
	var acmeIssuer *caddytls.ACMEIssuer
	if app.tlsApp.Automation != nil {
		// maybe we can find an exisitng one that matches; this is
		// useful if the user made a single automation policy to
		// set the CA endpoint to a test/staging endpoint (very
		// common), but forgot to customize the ports here, while
		// setting them in the HTTP app instead (I did this too
		// many times)
		for _, ap := range app.tlsApp.Automation.Policies {
			if len(ap.Hosts) == 0 {
				matchingPolicy = ap
				break
			}
		}
	}
	if matchingPolicy != nil {
		// if it has an ACME issuer, maybe we can just use that
		acmeIssuer, _ = matchingPolicy.Issuer.(*caddytls.ACMEIssuer)
	}
	if acmeIssuer == nil {
		acmeIssuer = new(caddytls.ACMEIssuer)
	}
	if acmeIssuer.Challenges == nil {
		acmeIssuer.Challenges = new(caddytls.ChallengesConfig)
	}
	if acmeIssuer.Challenges.HTTP == nil {
		acmeIssuer.Challenges.HTTP = new(caddytls.HTTPChallengeConfig)
	}
	if acmeIssuer.Challenges.HTTP.AlternatePort == 0 {
		// don't overwrite existing explicit config
		acmeIssuer.Challenges.HTTP.AlternatePort = app.HTTPPort
		acmeIssuer.Provision(ctx)
	}
	if acmeIssuer.Challenges.TLSALPN == nil {
		acmeIssuer.Challenges.TLSALPN = new(caddytls.TLSALPNChallengeConfig)
	}
	if acmeIssuer.Challenges.TLSALPN.AlternatePort == 0 {
		// don't overwrite existing explicit config
		acmeIssuer.Challenges.TLSALPN.AlternatePort = app.HTTPSPort
	}

	if matchingPolicy == nil {
		// if there was no matching policy, we'll have to append our own
		err := app.tlsApp.AddAutomationPolicy(&caddytls.AutomationPolicy{
			Hosts:  app.allCertDomains,
			Issuer: acmeIssuer,
		})
		if err != nil {
			return err
		}
	} else {
		// if there was an existing matching policy, we need to reprovision
		// its issuer (because we just changed its port settings and it has
		// to re-build its stored certmagic config template with the new
		// values), then re-assign the Issuer pointer on the policy struct
		// because our type assertion changed the address
		err := acmeIssuer.Provision(ctx)
		if err != nil {
			return err
		}
		matchingPolicy.Issuer = acmeIssuer
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
