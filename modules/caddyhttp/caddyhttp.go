package caddyhttp

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	weakrand "math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/modules/caddytls"
	"github.com/mholt/certmagic"
)

func init() {
	weakrand.Seed(time.Now().UnixNano())

	err := caddy.RegisterModule(caddy.Module{
		Name: "http",
		New:  func() interface{} { return new(App) },
	})
	if err != nil {
		log.Fatal(err)
	}
}

// App is the HTTP app for Caddy.
type App struct {
	HTTPPort    int                `json:"http_port,omitempty"`
	HTTPSPort   int                `json:"https_port,omitempty"`
	GracePeriod caddy.Duration     `json:"grace_period,omitempty"`
	Servers     map[string]*Server `json:"servers,omitempty"`

	servers []*http.Server

	ctx caddy.Context
}

// Provision sets up the app.
func (app *App) Provision(ctx caddy.Context) error {
	app.ctx = ctx

	repl := caddy.NewReplacer()

	for _, srv := range app.Servers {
		// TODO: Test this function to ensure these replacements are performed
		for i := range srv.Listen {
			srv.Listen[i] = repl.ReplaceAll(srv.Listen[i], "")
		}
		if srv.Routes != nil {
			err := srv.Routes.Provision(ctx)
			if err != nil {
				return fmt.Errorf("setting up server routes: %v", err)
			}
		}
		if srv.Errors != nil {
			err := srv.Errors.Routes.Provision(ctx)
			if err != nil {
				return fmt.Errorf("setting up server error handling routes: %v", err)
			}
		}
	}

	return nil
}

// Validate ensures the app's configuration is valid.
func (app *App) Validate() error {
	// each server must use distinct listener addresses
	lnAddrs := make(map[string]string)
	for srvName, srv := range app.Servers {
		for _, addr := range srv.Listen {
			netw, expanded, err := parseListenAddr(addr)
			if err != nil {
				return fmt.Errorf("invalid listener address '%s': %v", addr, err)
			}
			for _, a := range expanded {
				if sn, ok := lnAddrs[netw+a]; ok {
					return fmt.Errorf("listener address repeated: %s (already claimed by server '%s')", a, sn)
				}
				lnAddrs[netw+a] = srvName
			}
		}
	}

	// each server's max rehandle value must be valid
	for srvName, srv := range app.Servers {
		if srv.MaxRehandles < 0 {
			return fmt.Errorf("%s: invalid max_rehandles value: %d", srvName, srv.MaxRehandles)
		}
	}

	return nil
}

// Start runs the app. It sets up automatic HTTPS if enabled.
func (app *App) Start() error {
	err := app.automaticHTTPS()
	if err != nil {
		return fmt.Errorf("enabling automatic HTTPS: %v", err)
	}

	for srvName, srv := range app.Servers {
		s := &http.Server{
			ReadTimeout:       time.Duration(srv.ReadTimeout),
			ReadHeaderTimeout: time.Duration(srv.ReadHeaderTimeout),
			WriteTimeout:      time.Duration(srv.WriteTimeout),
			IdleTimeout:       time.Duration(srv.IdleTimeout),
			MaxHeaderBytes:    srv.MaxHeaderBytes,
			Handler:           srv,
		}

		for _, lnAddr := range srv.Listen {
			network, addrs, err := parseListenAddr(lnAddr)
			if err != nil {
				return fmt.Errorf("%s: parsing listen address '%s': %v", srvName, lnAddr, err)
			}
			for _, addr := range addrs {
				ln, err := caddy.Listen(network, addr)
				if err != nil {
					return fmt.Errorf("%s: listening on %s: %v", network, addr, err)
				}

				// enable HTTP/2 (and support for solving the
				// TLS-ALPN ACME challenge) by default
				for _, pol := range srv.TLSConnPolicies {
					if len(pol.ALPN) == 0 {
						pol.ALPN = append(pol.ALPN, defaultALPN...)
					}
				}

				// enable TLS
				httpPort := app.HTTPPort
				if httpPort == 0 {
					httpPort = DefaultHTTPPort
				}
				_, port, _ := net.SplitHostPort(addr)
				if len(srv.TLSConnPolicies) > 0 && port != strconv.Itoa(httpPort) {
					tlsCfg, err := srv.TLSConnPolicies.TLSConfig(app.ctx)
					if err != nil {
						return fmt.Errorf("%s/%s: making TLS configuration: %v", network, addr, err)
					}
					ln = tls.NewListener(ln, tlsCfg)
				}

				go s.Serve(ln)
				app.servers = append(app.servers, s)
			}
		}
	}

	return nil
}

// Stop gracefully shuts down the HTTP server.
func (app *App) Stop() error {
	ctx := context.Background()
	if app.GracePeriod > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(app.GracePeriod))
		defer cancel()
	}
	for _, s := range app.servers {
		err := s.Shutdown(ctx)
		if err != nil {
			return err
		}
	}
	return nil
}

func (app *App) automaticHTTPS() error {
	tlsAppIface, err := app.ctx.App("tls")
	if err != nil {
		return fmt.Errorf("getting tls app: %v", err)
	}
	tlsApp := tlsAppIface.(*caddytls.TLS)

	lnAddrMap := make(map[string]struct{})
	var redirRoutes RouteList

	for srvName, srv := range app.Servers {
		srv.tlsApp = tlsApp

		if srv.DisableAutoHTTPS {
			continue
		}

		// skip if all listeners use the HTTP port
		if !srv.listenersUseAnyPortOtherThan(app.HTTPPort) {
			continue
		}

		// find all qualifying domain names, de-duplicated
		domainSet := make(map[string]struct{})
		for _, route := range srv.Routes {
			for _, matcherSet := range route.matcherSets {
				for _, m := range matcherSet {
					if hm, ok := m.(*MatchHost); ok {
						for _, d := range *hm {
							if certmagic.HostQualifies(d) {
								domainSet[d] = struct{}{}
							}
						}
					}
				}
			}
		}

		if len(domainSet) > 0 {
			// marshal the domains into a slice
			var domains []string
			for d := range domainSet {
				domains = append(domains, d)
			}

			// ensure that these certificates are managed properly;
			// for example, it's implied that the HTTPPort should also
			// be the port the HTTP challenge is solved on, and so
			// for HTTPS port and TLS-ALPN challenge also - we need
			// to tell the TLS app to manage these certs by honoring
			// those port configurations
			acmeManager := &caddytls.ACMEManagerMaker{
				Challenges: caddytls.ChallengesConfig{
					HTTP: caddytls.HTTPChallengeConfig{
						AlternatePort: app.HTTPPort,
					},
					TLSALPN: caddytls.TLSALPNChallengeConfig{
						AlternatePort: app.HTTPSPort,
					},
				},
			}
			acmeManager.SetDefaults()
			tlsApp.Automation.Policies = append(tlsApp.Automation.Policies,
				caddytls.AutomationPolicy{
					Hosts:      domains,
					Management: acmeManager,
				})

			// manage their certificates
			err := tlsApp.Manage(domains)
			if err != nil {
				return fmt.Errorf("%s: managing certificate for %s: %s", srvName, domains, err)
			}

			// tell the server to use TLS by specifying a TLS
			// connection policy (which supports HTTP/2 and the
			// TLS-ALPN ACME challenge as well)
			srv.TLSConnPolicies = caddytls.ConnectionPolicies{
				{ALPN: defaultALPN},
			}

			if srv.DisableAutoHTTPSRedir {
				continue
			}

			// create HTTP->HTTPS redirects
			for _, addr := range srv.Listen {
				netw, host, port, err := splitListenAddr(addr)
				if err != nil {
					return fmt.Errorf("%s: invalid listener address: %v", srvName, addr)
				}

				httpPort := app.HTTPPort
				if httpPort == 0 {
					httpPort = DefaultHTTPPort
				}
				httpRedirLnAddr := joinListenAddr(netw, host, strconv.Itoa(httpPort))
				lnAddrMap[httpRedirLnAddr] = struct{}{}

				if parts := strings.SplitN(port, "-", 2); len(parts) == 2 {
					port = parts[0]
				}
				redirTo := "https://{http.request.host}"

				httpsPort := app.HTTPSPort
				if httpsPort == 0 {
					httpsPort = DefaultHTTPSPort
				}
				if port != strconv.Itoa(httpsPort) {
					redirTo += ":" + port
				}
				redirTo += "{http.request.uri}"

				redirRoutes = append(redirRoutes, ServerRoute{
					matcherSets: []MatcherSet{
						{
							MatchProtocol("http"),
							MatchHost(domains),
						},
					},
					responder: Static{
						StatusCode: http.StatusTemporaryRedirect, // TODO: use permanent redirect instead
						Headers: http.Header{
							"Location":   []string{redirTo},
							"Connection": []string{"close"},
						},
						Close: true,
					},
				})
			}
		}
	}

	if len(lnAddrMap) > 0 {
		var lnAddrs []string
	mapLoop:
		for addr := range lnAddrMap {
			netw, addrs, err := parseListenAddr(addr)
			if err != nil {
				continue
			}
			for _, a := range addrs {
				if app.listenerTaken(netw, a) {
					continue mapLoop
				}
			}
			lnAddrs = append(lnAddrs, addr)
		}
		app.Servers["auto_https_redirects"] = &Server{
			Listen:           lnAddrs,
			Routes:           redirRoutes,
			DisableAutoHTTPS: true,
			tlsApp:           tlsApp, // required to solve HTTP challenge
		}
	}

	return nil
}

func (app *App) listenerTaken(network, address string) bool {
	for _, srv := range app.Servers {
		for _, addr := range srv.Listen {
			netw, addrs, err := parseListenAddr(addr)
			if err != nil || netw != network {
				continue
			}
			for _, a := range addrs {
				if a == address {
					return true
				}
			}
		}
	}
	return false
}

var defaultALPN = []string{"h2", "http/1.1"}

// RequestMatcher is a type that can match to a request.
// A route matcher MUST NOT modify the request.
type RequestMatcher interface {
	Match(*http.Request) bool
}

// Middleware chains one Handler to the next by being passed
// the next Handler in the chain.
type Middleware func(HandlerFunc) HandlerFunc

// MiddlewareHandler is a Handler that includes a reference
// to the next middleware handler in the chain. Middleware
// handlers MUST NOT call Write() or WriteHeader() on the
// response writer; doing so will panic. See Handler godoc
// for more information.
type MiddlewareHandler interface {
	ServeHTTP(http.ResponseWriter, *http.Request, Handler) error
}

// Handler is like http.Handler except ServeHTTP may return an error.
//
// Middleware and responder handlers both implement this method.
// Middleware must not call Write or WriteHeader on the ResponseWriter;
// doing so will cause a panic. Responders should write to the response
// if there was not an error.
//
// If any handler encounters an error, it should be returned for proper
// handling. Return values should be propagated down the middleware chain
// by returning it unchanged. Returned errors should not be re-wrapped.
type Handler interface {
	ServeHTTP(http.ResponseWriter, *http.Request) error
}

// HandlerFunc is a convenience type like http.HandlerFunc.
type HandlerFunc func(http.ResponseWriter, *http.Request) error

// ServeHTTP implements the Handler interface.
func (f HandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	return f(w, r)
}

// emptyHandler is used as a no-op handler, which is
// sometimes better than a nil Handler pointer.
var emptyHandler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error { return nil }

func parseListenAddr(a string) (network string, addrs []string, err error) {
	var host, port string
	network, host, port, err = splitListenAddr(a)
	if network == "" {
		network = "tcp"
	}
	if err != nil {
		return
	}
	ports := strings.SplitN(port, "-", 2)
	if len(ports) == 1 {
		ports = append(ports, ports[0])
	}
	var start, end int
	start, err = strconv.Atoi(ports[0])
	if err != nil {
		return
	}
	end, err = strconv.Atoi(ports[1])
	if err != nil {
		return
	}
	if end < start {
		err = fmt.Errorf("end port must be greater than start port")
		return
	}
	for p := start; p <= end; p++ {
		addrs = append(addrs, net.JoinHostPort(host, fmt.Sprintf("%d", p)))
	}
	return
}

func splitListenAddr(a string) (network, host, port string, err error) {
	if idx := strings.Index(a, "/"); idx >= 0 {
		network = strings.ToLower(strings.TrimSpace(a[:idx]))
		a = a[idx+1:]
	}
	host, port, err = net.SplitHostPort(a)
	return
}

func joinListenAddr(network, host, port string) string {
	var a string
	if network != "" {
		a = network + "/"
	}
	a += host
	if port != "" {
		a += ":" + port
	}
	return a
}

const (
	// DefaultHTTPPort is the default port for HTTP.
	DefaultHTTPPort = 80

	// DefaultHTTPSPort is the default port for HTTPS.
	DefaultHTTPSPort = 443
)

// Interface guard
var _ caddy.App = (*App)(nil)
