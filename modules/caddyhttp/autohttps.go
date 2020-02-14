package caddyhttp

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/mholt/certmagic"
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

	domainSet map[string]struct{}
}

// Skipped returns true if name is in skipSlice, which
// should be one of the Skip* fields on ahc.
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

		// find all qualifying domain names in this server
		srv.AutoHTTPS.domainSet = make(map[string]struct{})
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
								srv.AutoHTTPS.domainSet[d] = struct{}{}
							}
						}
					}
				}
			}
		}

		// nothing more to do here if there are no
		// domains that qualify for automatic HTTPS
		if len(srv.AutoHTTPS.domainSet) == 0 {
			continue
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

// automaticHTTPSPhase2 attaches a TLS app pointer to each
// server. This phase must occur after provisioning, and
// at the beginning of the app start, before starting each
// of the servers.
func (app *App) automaticHTTPSPhase2() error {
	tlsAppIface, err := app.ctx.App("tls")
	if err != nil {
		return fmt.Errorf("getting tls app: %v", err)
	}
	tlsApp := tlsAppIface.(*caddytls.TLS)

	// set the tlsApp pointer before starting any
	// challenges, since it is required to solve
	// the ACME HTTP challenge
	for _, srv := range app.Servers {
		srv.tlsApp = tlsApp
	}

	return nil
}

// automaticHTTPSPhase3 begins certificate management for
// all names in the qualifying domain set for each server.
// This phase must occur after provisioning and at the end
// of app start, after all the servers have been started.
// Doing this last ensures that there won't be any race
// for listeners on the HTTP or HTTPS ports when management
// is async (if CertMagic's solvers bind to those ports
// first, then our servers would fail to bind to them,
// which would be bad, since CertMagic's bindings are
// temporary and don't serve the user's sites!).
func (app *App) automaticHTTPSPhase3() error {
	// begin managing certificates for enabled servers
	for srvName, srv := range app.Servers {
		if srv.AutoHTTPS == nil ||
			srv.AutoHTTPS.Disabled ||
			len(srv.AutoHTTPS.domainSet) == 0 {
			continue
		}

		// marshal the domains into a slice
		var domains, domainsForCerts []string
		for d := range srv.AutoHTTPS.domainSet {
			domains = append(domains, d)
			if !srv.AutoHTTPS.Skipped(d, srv.AutoHTTPS.SkipCerts) {
				// if a certificate for this name is already loaded,
				// don't obtain another one for it, unless we are
				// supposed to ignore loaded certificates
				if !srv.AutoHTTPS.IgnoreLoadedCerts &&
					len(srv.tlsApp.AllMatchingCertificates(d)) > 0 {
					app.logger.Info("skipping automatic certificate management because one or more matching certificates are already loaded",
						zap.String("domain", d),
						zap.String("server_name", srvName),
					)
					continue
				}
				domainsForCerts = append(domainsForCerts, d)
			}
		}

		// ensure that these certificates are managed properly;
		// for example, it's implied that the HTTPPort should also
		// be the port the HTTP challenge is solved on, and so
		// for HTTPS port and TLS-ALPN challenge also - we need
		// to tell the TLS app to manage these certs by honoring
		// those port configurations
		acmeManager := &caddytls.ACMEManagerMaker{
			Challenges: &caddytls.ChallengesConfig{
				HTTP: &caddytls.HTTPChallengeConfig{
					AlternatePort: app.HTTPPort, // we specifically want the user-configured port, if any
				},
				TLSALPN: &caddytls.TLSALPNChallengeConfig{
					AlternatePort: app.HTTPSPort, // we specifically want the user-configured port, if any
				},
			},
		}
		if srv.tlsApp.Automation == nil {
			srv.tlsApp.Automation = new(caddytls.AutomationConfig)
		}
		srv.tlsApp.Automation.Policies = append(srv.tlsApp.Automation.Policies,
			&caddytls.AutomationPolicy{
				Hosts:      domainsForCerts,
				Management: acmeManager,
			})

		// manage their certificates
		app.logger.Info("enabling automatic TLS certificate management",
			zap.Strings("domains", domainsForCerts),
		)
		err := srv.tlsApp.Manage(domainsForCerts)
		if err != nil {
			return fmt.Errorf("%s: managing certificate for %s: %s", srvName, domains, err)
		}

		// no longer needed; allow GC to deallocate
		srv.AutoHTTPS.domainSet = nil
	}

	return nil
}
