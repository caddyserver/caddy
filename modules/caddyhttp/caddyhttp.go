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

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
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
		if srv.AutoHTTPS == nil {
			// avoid nil pointer dereferences
			srv.AutoHTTPS = new(AutoHTTPSConfig)
		}

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
			netw, expanded, err := caddy.ParseListenAddr(addr)
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
			network, addrs, err := caddy.ParseListenAddr(lnAddr)
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

		if srv.AutoHTTPS.Disabled {
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
					Hosts:      domainsForCerts,
					Management: acmeManager,
				})

			// manage their certificates
			log.Printf("[INFO] Enabling automatic HTTPS certificates for %v", domainsForCerts)
			err := tlsApp.Manage(domainsForCerts)
			if err != nil {
				return fmt.Errorf("%s: managing certificate for %s: %s", srvName, domains, err)
			}

			// tell the server to use TLS by specifying a TLS
			// connection policy (which supports HTTP/2 and the
			// TLS-ALPN ACME challenge as well)
			srv.TLSConnPolicies = caddytls.ConnectionPolicies{
				{ALPN: defaultALPN},
			}

			if srv.AutoHTTPS.DisableRedir {
				continue
			}

			log.Printf("[INFO] Enabling automatic HTTP->HTTPS redirects for %v", domains)

			// create HTTP->HTTPS redirects
			for _, addr := range srv.Listen {
				netw, host, port, err := caddy.SplitListenAddr(addr)
				if err != nil {
					return fmt.Errorf("%s: invalid listener address: %v", srvName, addr)
				}

				httpPort := app.HTTPPort
				if httpPort == 0 {
					httpPort = DefaultHTTPPort
				}
				httpRedirLnAddr := caddy.JoinListenAddr(netw, host, strconv.Itoa(httpPort))
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
					handlers: []MiddlewareHandler{
						StaticResponse{
							StatusCode: weakString(strconv.Itoa(http.StatusTemporaryRedirect)), // TODO: use permanent redirect instead
							Headers: http.Header{
								"Location":   []string{redirTo},
								"Connection": []string{"close"},
							},
							Close: true,
						},
					},
				})
			}
		}
	}

	if len(lnAddrMap) > 0 {
		var lnAddrs []string
	mapLoop:
		for addr := range lnAddrMap {
			netw, addrs, err := caddy.ParseListenAddr(addr)
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
			Listen:    lnAddrs,
			Routes:    redirRoutes,
			AutoHTTPS: &AutoHTTPSConfig{Disabled: true},
			tlsApp:    tlsApp, // required to solve HTTP challenge
		}
	}

	return nil
}

func (app *App) listenerTaken(network, address string) bool {
	for _, srv := range app.Servers {
		for _, addr := range srv.Listen {
			netw, addrs, err := caddy.ParseListenAddr(addr)
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
