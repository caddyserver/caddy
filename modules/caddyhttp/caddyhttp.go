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
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	weakrand "math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/mholt/certmagic"
	"go.uber.org/zap"
)

func init() {
	weakrand.Seed(time.Now().UnixNano())

	err := caddy.RegisterModule(App{})
	if err != nil {
		caddy.Log().Fatal(err.Error())
	}
}

// App is a robust, production-ready HTTP server.
//
// HTTPS is enabled by default if host matchers with qualifying names are used
// in any of routes; certificates are automatically provisioned and renewed.
// Additionally, automatic HTTPS will also enable HTTPS for servers that listen
// only on the HTTPS port but which do not have any TLS connection policies
// defined by adding a good, default TLS connection policy.
//
// In HTTP routes, additional placeholders are available:
//
// Placeholder | Description
// ------------|---------------
// `{http.request.cookie.*}` | HTTP request cookie
// `{http.request.header.*}` | Specific request header field
// `{http.request.host.labels.*}` | Request host labels (0-based from right); e.g. for foo.example.com: 0=com, 1=example, 2=foo
// `{http.request.host}` | The host part of the request's Host header
// `{http.request.hostport}` | The host and port from the request's Host header
// `{http.request.method}` | The request method
// `{http.request.orig.method}` | The request's original method
// `{http.request.orig.path.dir}` | The request's original directory
// `{http.request.orig.path.file}` | The request's original filename
// `{http.request.orig.uri.path}` | The request's original path
// `{http.request.orig.uri.query_string}` | The request's original full query string (with `?`)
// `{http.request.orig.uri.query}` | The request's original query string (without `?`)
// `{http.request.orig.uri}` | The request's original URI
// `{http.request.port}` | The port part of the request's Host header
// `{http.request.proto}` | The protocol of the request
// `{http.request.remote.host}` | The host part of the remote client's address
// `{http.request.remote.port}` | The port part of the remote client's address
// `{http.request.remote}` | The address of the remote client
// `{http.request.scheme}` | The request scheme
// `{http.request.uri.path.*}` | Parts of the path, split by `/` (0-based from left)
// `{http.request.uri.path.dir}` | The directory, excluding leaf filename
// `{http.request.uri.path.file}` | The filename of the path, excluding directory
// `{http.request.uri.path}` | The path component of the request URI
// `{http.request.uri.query_string}` | The full query string (with `?`)
// `{http.request.uri.query.*}` | Individual query string value
// `{http.request.uri.query}` | The query string (without `?`)
// `{http.request.uri}` | The full request URI
// `{http.response.header.*}` | Specific response header field
// `{http.vars.*}` | Custom variables in the HTTP handler chain
type App struct {
	// HTTPPort specifies the port to use for HTTP (as opposed to HTTPS),
	// which is used when setting up HTTP->HTTPS redirects or ACME HTTP
	// challenge solvers. Default: 80.
	HTTPPort int `json:"http_port,omitempty"`

	// HTTPSPort specifies the port to use for HTTPS, which is used when
	// solving the ACME TLS-ALPN challenges, or whenever HTTPS is needed
	// but no specific port number is given. Default: 443.
	HTTPSPort int `json:"https_port,omitempty"`

	// GracePeriod is how long to wait for active connections when shutting
	// down the server. Once the grace period is over, connections will
	// be forcefully closed.
	GracePeriod caddy.Duration `json:"grace_period,omitempty"`

	// Servers is the list of servers, keyed by arbitrary names chosen
	// at your discretion for your own convenience; the keys do not
	// affect functionality.
	Servers map[string]*Server `json:"servers,omitempty"`

	servers     []*http.Server
	h3servers   []*http3.Server
	h3listeners []net.PacketConn

	ctx    caddy.Context
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http",
		New: func() caddy.Module { return new(App) },
	}
}

// Provision sets up the app.
func (app *App) Provision(ctx caddy.Context) error {
	app.ctx = ctx
	app.logger = ctx.Logger(app)

	repl := caddy.NewReplacer()

	for srvName, srv := range app.Servers {
		srv.logger = app.logger.Named("log")
		srv.errorLogger = app.logger.Named("log.error")

		// only enable access logs if configured
		if srv.Logs != nil {
			srv.accessLogger = app.logger.Named("log.access")
		}

		if srv.AutoHTTPS == nil {
			// avoid nil pointer dereferences
			srv.AutoHTTPS = new(AutoHTTPSConfig)
		}

		// if not explicitly configured by the user, disallow TLS
		// client auth bypass (domain fronting) which could
		// otherwise be exploited by sending an unprotected SNI
		// value during a TLS handshake, then putting a protected
		// domain in the Host header after establishing connection;
		// this is a safe default, but we allow users to override
		// it for example in the case of running a proxy where
		// domain fronting is desired and access is not restricted
		// based on hostname
		if srv.StrictSNIHost == nil && srv.hasTLSClientAuth() {
			trueBool := true
			srv.StrictSNIHost = &trueBool
		}

		for i := range srv.Listen {
			lnOut, err := repl.ReplaceOrErr(srv.Listen[i], true, true)
			if err != nil {
				return fmt.Errorf("server %s, listener %d: %v",
					srvName, i, err)
			}
			srv.Listen[i] = lnOut
		}

		if srv.Routes != nil {
			err := srv.Routes.Provision(ctx)
			if err != nil {
				return fmt.Errorf("server %s: setting up server routes: %v", srvName, err)
			}
			// pre-compile the handler chain, and be sure to wrap it in our
			// route handler so that important security checks are done, etc.
			srv.primaryHandlerChain = srv.wrapPrimaryRoute(srv.Routes.Compile())
		}

		if srv.Errors != nil {
			err := srv.Errors.Routes.Provision(ctx)
			if err != nil {
				return fmt.Errorf("server %s: setting up server error handling routes: %v", srvName, err)
			}
			srv.errorHandlerChain = srv.Errors.Routes.Compile()
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
			listenAddr, err := caddy.ParseNetworkAddress(addr)
			if err != nil {
				return fmt.Errorf("invalid listener address '%s': %v", addr, err)
			}
			// check that every address in the port range is unique to this server;
			// we do not use <= here because PortRangeSize() adds 1 to EndPort for us
			for i := uint(0); i < listenAddr.PortRangeSize(); i++ {
				addr := caddy.JoinNetworkAddress(listenAddr.Network, listenAddr.Host, strconv.Itoa(int(listenAddr.StartPort+i)))
				if sn, ok := lnAddrs[addr]; ok {
					return fmt.Errorf("server %s: listener address repeated: %s (already claimed by server '%s')", srvName, addr, sn)
				}
				lnAddrs[addr] = srvName
			}
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
			listenAddr, err := caddy.ParseNetworkAddress(lnAddr)
			if err != nil {
				return fmt.Errorf("%s: parsing listen address '%s': %v", srvName, lnAddr, err)
			}
			for i := uint(0); i < listenAddr.PortRangeSize(); i++ {
				hostport := listenAddr.JoinHostPort(i)
				ln, err := caddy.Listen(listenAddr.Network, hostport)
				if err != nil {
					return fmt.Errorf("%s: listening on %s: %v", listenAddr.Network, hostport, err)
				}

				// enable HTTP/2 by default
				for _, pol := range srv.TLSConnPolicies {
					if len(pol.ALPN) == 0 {
						pol.ALPN = append(pol.ALPN, defaultALPN...)
					}
				}

				// enable TLS
				if len(srv.TLSConnPolicies) > 0 && int(i) != app.httpPort() {
					tlsCfg, err := srv.TLSConnPolicies.TLSConfig(app.ctx)
					if err != nil {
						return fmt.Errorf("%s/%s: making TLS configuration: %v", listenAddr.Network, hostport, err)
					}
					ln = tls.NewListener(ln, tlsCfg)

					/////////
					// TODO: HTTP/3 support is experimental for now
					if srv.ExperimentalHTTP3 {
						app.logger.Info("enabling experimental HTTP/3 listener",
							zap.String("addr", hostport),
						)
						h3ln, err := caddy.ListenPacket("udp", hostport)
						if err != nil {
							return fmt.Errorf("getting HTTP/3 UDP listener: %v", err)
						}
						h3srv := &http3.Server{
							Server: &http.Server{
								Addr:      hostport,
								Handler:   srv,
								TLSConfig: tlsCfg,
							},
						}
						go h3srv.Serve(h3ln)
						app.h3servers = append(app.h3servers, h3srv)
						app.h3listeners = append(app.h3listeners, h3ln)
						srv.h3server = h3srv
					}
					/////////
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
	// TODO: Closing the http3.Server is the right thing to do,
	// however, doing so sometimes causes connections from clients
	// to fail after config reloads due to a bug that is yet
	// unsolved: https://github.com/caddyserver/caddy/pull/2727
	// for _, s := range app.h3servers {
	// 	// TODO: CloseGracefully, once implemented upstream
	// 	// (see https://github.com/lucas-clemente/quic-go/issues/2103)
	// 	err := s.Close()
	// 	if err != nil {
	// 		return err
	// 	}
	// }
	// as of September 2019, closing the http3.Server
	// instances doesn't close their underlying listeners
	// so we have todo that ourselves
	// (see https://github.com/lucas-clemente/quic-go/issues/2103)
	for _, pc := range app.h3listeners {
		err := pc.Close()
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

	// this map will store associations of HTTP listener
	// addresses to the routes that do HTTP->HTTPS redirects
	lnAddrRedirRoutes := make(map[string]Route)

	repl := caddy.NewReplacer()

	for srvName, srv := range app.Servers {
		srv.tlsApp = tlsApp

		if srv.AutoHTTPS.Disabled {
			continue
		}

		// skip if all listeners use the HTTP port
		if !srv.listenersUseAnyPortOtherThan(app.httpPort()) {
			app.logger.Info("server is only listening on the HTTP port, so no automatic HTTPS will be applied to this server",
				zap.String("server_name", srvName),
				zap.Int("http_port", app.httpPort()),
			)
			continue
		}

		// if all listeners are on the HTTPS port, make sure
		// there is at least one TLS connection policy; it
		// should be obvious that they want to use TLS without
		// needing to specify one empty policy to enable it
		if !srv.listenersUseAnyPortOtherThan(app.httpsPort()) && len(srv.TLSConnPolicies) == 0 {
			app.logger.Info("server is only listening on the HTTPS port but has no TLS connection policies; adding one to enable TLS",
				zap.String("server_name", srvName),
				zap.Int("https_port", app.httpsPort()),
			)
			srv.TLSConnPolicies = append(srv.TLSConnPolicies, new(caddytls.ConnectionPolicy))
		}

		// find all qualifying domain names, de-duplicated
		domainSet := make(map[string]struct{})
		for routeIdx, route := range srv.Routes {
			for matcherSetIdx, matcherSet := range route.MatcherSets {
				for matcherIdx, m := range matcherSet {
					if hm, ok := m.(*MatchHost); ok {
						for hostMatcherIdx, d := range *hm {
							d, err = repl.ReplaceOrErr(d, true, false)
							if err != nil {
								return fmt.Errorf("%s: route %d, matcher set %d, matcher %d, host matcher %d: %v",
									srvName, routeIdx, matcherSetIdx, matcherIdx, hostMatcherIdx, err)
							}
							if certmagic.HostQualifies(d) &&
								!srv.AutoHTTPS.Skipped(d, srv.AutoHTTPS.Skip) {
								domainSet[d] = struct{}{}
							}
						}
					}
				}
			}
		}

		if len(domainSet) > 0 {
			// marshal the domains into a slice
			var domains, domainsForCerts []string
			for d := range domainSet {
				domains = append(domains, d)
				if !srv.AutoHTTPS.Skipped(d, srv.AutoHTTPS.SkipCerts) {
					// if a certificate for this name is already loaded,
					// don't obtain another one for it, unless we are
					// supposed to ignore loaded certificates
					if !srv.AutoHTTPS.IgnoreLoadedCerts &&
						len(tlsApp.AllMatchingCertificates(d)) > 0 {
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
			if tlsApp.Automation == nil {
				tlsApp.Automation = new(caddytls.AutomationConfig)
			}
			tlsApp.Automation.Policies = append(tlsApp.Automation.Policies,
				caddytls.AutomationPolicy{
					Hosts:      domainsForCerts,
					Management: acmeManager,
				})

			// manage their certificates
			app.logger.Info("enabling automatic TLS certificate management",
				zap.Strings("domains", domainsForCerts),
			)
			err := tlsApp.Manage(domainsForCerts)
			if err != nil {
				return fmt.Errorf("%s: managing certificate for %s: %s", srvName, domains, err)
			}

			// tell the server to use TLS if it is not already doing so
			if srv.TLSConnPolicies == nil {
				srv.TLSConnPolicies = caddytls.ConnectionPolicies{
					&caddytls.ConnectionPolicy{ALPN: defaultALPN},
				}
			}

			if srv.AutoHTTPS.DisableRedir {
				continue
			}

			app.logger.Info("enabling automatic HTTP->HTTPS redirects",
				zap.Strings("domains", domains),
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

				// create the route that does the redirect and associate
				// it with the listener address it will be served from
				lnAddrRedirRoutes[httpRedirLnAddr] = Route{
					MatcherSets: []MatcherSet{
						{
							MatchProtocol("http"),
							MatchHost(domains),
						},
					},
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
	}

	// if there are HTTP->HTTPS redirects to add, do so now
	if len(lnAddrRedirRoutes) > 0 {
		var redirServerAddrs []string
		var redirRoutes []Route

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
				Listen:      redirServerAddrs,
				Routes:      redirRoutes,
				tlsApp:      tlsApp, // required to solve HTTP challenge
				logger:      app.logger.Named("log"),
				errorLogger: app.logger.Named("log.error"),
			}
		}
	}

	return nil
}

func (app *App) httpPort() int {
	if app.HTTPPort == 0 {
		return DefaultHTTPPort
	}
	return app.HTTPPort
}

func (app *App) httpsPort() int {
	if app.HTTPSPort == 0 {
		return DefaultHTTPSPort
	}
	return app.HTTPSPort
}

var defaultALPN = []string{"h2", "http/1.1"}

// RequestMatcher is a type that can match to a request.
// A route matcher MUST NOT modify the request, with the
// only exception being its context.
type RequestMatcher interface {
	Match(*http.Request) bool
}

// Handler is like http.Handler except ServeHTTP may return an error.
//
// If any handler encounters an error, it should be returned for proper
// handling. Return values should be propagated down the middleware chain
// by returning it unchanged. Returned errors should not be re-wrapped
// if they are already HandlerError values.
type Handler interface {
	ServeHTTP(http.ResponseWriter, *http.Request) error
}

// HandlerFunc is a convenience type like http.HandlerFunc.
type HandlerFunc func(http.ResponseWriter, *http.Request) error

// ServeHTTP implements the Handler interface.
func (f HandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	return f(w, r)
}

// Middleware chains one Handler to the next by being passed
// the next Handler in the chain.
type Middleware func(Handler) Handler

// MiddlewareHandler is like Handler except it takes as a third
// argument the next handler in the chain. The next handler will
// never be nil, but may be a no-op handler if this is the last
// handler in the chain. Handlers which act as middleware should
// call the next handler's ServeHTTP method so as to propagate
// the request down the chain properly. Handlers which act as
// responders (content origins) need not invoke the next handler,
// since the last handler in the chain should be the first to
// write the response.
type MiddlewareHandler interface {
	ServeHTTP(http.ResponseWriter, *http.Request, Handler) error
}

// emptyHandler is used as a no-op handler.
var emptyHandler Handler = HandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil })

// WeakString is a type that unmarshals any JSON value
// as a string literal, with the following exceptions:
//
// 1. actual string values are decoded as strings; and
// 2. null is decoded as empty string;
//
// and provides methods for getting the value as various
// primitive types. However, using this type removes any
// type safety as far as deserializing JSON is concerned.
type WeakString string

// UnmarshalJSON satisfies json.Unmarshaler according to
// this type's documentation.
func (ws *WeakString) UnmarshalJSON(b []byte) error {
	if len(b) == 0 {
		return io.EOF
	}
	if b[0] == byte('"') && b[len(b)-1] == byte('"') {
		var s string
		err := json.Unmarshal(b, &s)
		if err != nil {
			return err
		}
		*ws = WeakString(s)
		return nil
	}
	if bytes.Equal(b, []byte("null")) {
		return nil
	}
	*ws = WeakString(b)
	return nil
}

// MarshalJSON marshals was a boolean if true or false,
// a number if an integer, or a string otherwise.
func (ws WeakString) MarshalJSON() ([]byte, error) {
	if ws == "true" {
		return []byte("true"), nil
	}
	if ws == "false" {
		return []byte("false"), nil
	}
	if num, err := strconv.Atoi(string(ws)); err == nil {
		return json.Marshal(num)
	}
	return json.Marshal(string(ws))
}

// Int returns ws as an integer. If ws is not an
// integer, 0 is returned.
func (ws WeakString) Int() int {
	num, _ := strconv.Atoi(string(ws))
	return num
}

// Float64 returns ws as a float64. If ws is not a
// float value, the zero value is returned.
func (ws WeakString) Float64() float64 {
	num, _ := strconv.ParseFloat(string(ws), 64)
	return num
}

// Bool returns ws as a boolean. If ws is not a
// boolean, false is returned.
func (ws WeakString) Bool() bool {
	return string(ws) == "true"
}

// String returns ws as a string.
func (ws WeakString) String() string {
	return string(ws)
}

// CopyHeader copies HTTP headers by completely
// replacing dest with src. (This allows deletions
// to be propagated, assuming src started as a
// consistent copy of dest.)
func CopyHeader(dest, src http.Header) {
	for field := range dest {
		delete(dest, field)
	}
	for field, val := range src {
		dest[field] = val
	}
}

// StatusCodeMatches returns true if a real HTTP status code matches
// the configured status code, which may be either a real HTTP status
// code or an integer representing a class of codes (e.g. 4 for all
// 4xx statuses).
func StatusCodeMatches(actual, configured int) bool {
	if actual == configured {
		return true
	}
	if configured < 100 && actual >= configured*100 && actual < (configured+1)*100 {
		return true
	}
	return false
}

const (
	// DefaultHTTPPort is the default port for HTTP.
	DefaultHTTPPort = 80

	// DefaultHTTPSPort is the default port for HTTPS.
	DefaultHTTPSPort = 443
)

// Interface guards
var (
	_ caddy.App         = (*App)(nil)
	_ caddy.Provisioner = (*App)(nil)
	_ caddy.Validator   = (*App)(nil)
)
