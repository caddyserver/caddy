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
	"log"
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
)

func init() {
	weakrand.Seed(time.Now().UnixNano())

	err := caddy.RegisterModule(App{})
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

	servers     []*http.Server
	h3servers   []*http3.Server
	h3listeners []net.PacketConn

	ctx caddy.Context
}

// CaddyModule returns the Caddy module information.
func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		Name: "http",
		New:  func() caddy.Module { return new(App) },
	}
}

// Provision sets up the app.
func (app *App) Provision(ctx caddy.Context) error {
	app.ctx = ctx

	repl := caddy.NewReplacer()

	for _, srv := range app.Servers {
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

		if srv.MaxRehandles == nil {
			srv.MaxRehandles = &DefaultMaxRehandles
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
			netw, expanded, err := caddy.ParseNetworkAddress(addr)
			if err != nil {
				return fmt.Errorf("invalid listener address '%s': %v", addr, err)
			}
			for _, a := range expanded {
				if sn, ok := lnAddrs[netw+a]; ok {
					return fmt.Errorf("server %s: listener address repeated: %s (already claimed by server '%s')", srvName, a, sn)
				}
				lnAddrs[netw+a] = srvName
			}
		}
	}

	// each server's max rehandle value must be valid
	for srvName, srv := range app.Servers {
		if srv.MaxRehandles != nil && *srv.MaxRehandles < 0 {
			return fmt.Errorf("%s: invalid max_rehandles value: %d", srvName, *srv.MaxRehandles)
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
			network, addrs, err := caddy.ParseNetworkAddress(lnAddr)
			if err != nil {
				return fmt.Errorf("%s: parsing listen address '%s': %v", srvName, lnAddr, err)
			}
			for _, addr := range addrs {
				ln, err := caddy.Listen(network, addr)
				if err != nil {
					return fmt.Errorf("%s: listening on %s: %v", network, addr, err)
				}

				// enable HTTP/2 by default
				for _, pol := range srv.TLSConnPolicies {
					if len(pol.ALPN) == 0 {
						pol.ALPN = append(pol.ALPN, defaultALPN...)
					}
				}

				// enable TLS
				_, port, _ := net.SplitHostPort(addr)
				if len(srv.TLSConnPolicies) > 0 && port != strconv.Itoa(app.httpPort()) {
					tlsCfg, err := srv.TLSConnPolicies.TLSConfig(app.ctx)
					if err != nil {
						return fmt.Errorf("%s/%s: making TLS configuration: %v", network, addr, err)
					}
					ln = tls.NewListener(ln, tlsCfg)

					/////////
					// TODO: HTTP/3 support is experimental for now
					if srv.ExperimentalHTTP3 {
						log.Printf("[INFO] Enabling experimental HTTP/3 listener on %s", addr)
						h3ln, err := caddy.ListenPacket("udp", addr)
						if err != nil {
							return fmt.Errorf("getting HTTP/3 UDP listener: %v", err)
						}
						h3srv := &http3.Server{
							Server: &http.Server{
								Addr:      addr,
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

	for srvName, srv := range app.Servers {
		srv.tlsApp = tlsApp

		if srv.AutoHTTPS.Disabled {
			continue
		}

		// skip if all listeners use the HTTP port
		if !srv.listenersUseAnyPortOtherThan(app.httpPort()) {
			log.Printf("[INFO] Server %s is only listening on the HTTP port %d, so no automatic HTTPS will be applied to this server",
				srvName, app.httpPort())
			continue
		}

		// find all qualifying domain names, de-duplicated
		domainSet := make(map[string]struct{})
		for _, route := range srv.Routes {
			for _, matcherSet := range route.MatcherSets {
				for _, m := range matcherSet {
					if hm, ok := m.(*MatchHost); ok {
						for _, d := range *hm {
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
						log.Printf("[INFO][%s] Skipping automatic certificate management because one or more matching certificates are already loaded", d)
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
			log.Printf("[INFO] Enabling automatic TLS certificate management for %v", domainsForCerts)
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

			log.Printf("[INFO] Enabling automatic HTTP->HTTPS redirects for %v", domains)

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
							StatusCode: WeakString(strconv.Itoa(http.StatusTemporaryRedirect)), // TODO: use permanent redirect instead
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
		// server configured to listen on that exact address; if
		// so, simply the redirect route to the end of its route
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
					log.Printf("[WARNING] Server %s is listening on %s, so automatic HTTP->HTTPS redirects might be overridden by your own configuration",
						srvName, addr)
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
				tlsApp: tlsApp, // required to solve HTTP challenge
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
type Middleware func(HandlerFunc) HandlerFunc

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
var emptyHandler HandlerFunc = func(http.ResponseWriter, *http.Request) error { return nil }

// WeakString is a type that unmarshals any JSON value
// as a string literal, with the following exceptions:
// 1) actual string values are decoded as strings, and
// 2) null is decoded as empty string
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

// DefaultMaxRehandles is the maximum number of rehandles to
// allow, if not specified explicitly.
var DefaultMaxRehandles = 3

// Interface guards
var (
	_ caddy.App         = (*App)(nil)
	_ caddy.Provisioner = (*App)(nil)
	_ caddy.Validator   = (*App)(nil)
)
