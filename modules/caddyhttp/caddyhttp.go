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
	"time"

	"github.com/caddyserver/caddy/v2"
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
// In HTTP routes, additional placeholders are available (replace any `*`):
//
// Placeholder | Description
// ------------|---------------
// `{http.request.cookie.*}` | HTTP request cookie
// `{http.request.header.*}` | Specific request header field
// `{http.request.host.labels.*}` | Request host labels (0-based from right); e.g. for foo.example.com: 0=com, 1=example, 2=foo
// `{http.request.host}` | The host part of the request's Host header
// `{http.request.hostport}` | The host and port from the request's Host header
// `{http.request.method}` | The request method
// `{http.request.orig_method}` | The request's original method
// `{http.request.orig_uri.path.dir}` | The request's original directory
// `{http.request.orig_uri.path.file}` | The request's original filename
// `{http.request.orig_uri.path}` | The request's original path
// `{http.request.orig_uri.query}` | The request's original query string (without `?`)
// `{http.request.orig_uri}` | The request's original URI
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

	// DefaultSNI if set configures all certificate lookups to fallback to use
	// this SNI name if a more specific certificate could not be found
	DefaultSNI string `json:"default_sni,omitempty"`

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

	certmagic.Default.DefaultServerName = app.DefaultSNI

	// this provisions the matchers for each route,
	// and prepares auto HTTP->HTTP redirects, and
	// is required before we provision each server
	err := app.automaticHTTPSPhase1(ctx, repl)
	if err != nil {
		return err
	}

	for srvName, srv := range app.Servers {
		srv.logger = app.logger.Named("log")
		srv.errorLogger = app.logger.Named("log.error")

		// only enable access logs if configured
		if srv.Logs != nil {
			srv.accessLogger = app.logger.Named("log.access")
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
			app.logger.Info("enabling strict SNI-Host matching because TLS client auth is configured",
				zap.String("server_name", srvName),
			)
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

		// pre-compile the primary handler chain, and be sure to wrap it in our
		// route handler so that important security checks are done, etc.
		primaryRoute := emptyHandler
		if srv.Routes != nil {
			err := srv.Routes.ProvisionHandlers(ctx)
			if err != nil {
				return fmt.Errorf("server %s: setting up route handlers: %v", srvName, err)
			}
			primaryRoute = srv.Routes.Compile(emptyHandler)
		}
		srv.primaryHandlerChain = srv.wrapPrimaryRoute(primaryRoute)

		// pre-compile the error handler chain
		if srv.Errors != nil {
			err := srv.Errors.Routes.Provision(ctx)
			if err != nil {
				return fmt.Errorf("server %s: setting up server error handling routes: %v", srvName, err)
			}
			srv.errorHandlerChain = srv.Errors.Routes.Compile(emptyHandler)
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

// Start runs the app. It finishes automatic HTTPS if enabled,
// including management of certificates.
func (app *App) Start() error {
	// give each server a pointer to the TLS app;
	// this is required before they are started so
	// they can solve ACME challenges
	err := app.automaticHTTPSPhase2()
	if err != nil {
		return fmt.Errorf("enabling automatic HTTPS, phase 2: %v", err)
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
			for portOffset := uint(0); portOffset < listenAddr.PortRangeSize(); portOffset++ {
				hostport := listenAddr.JoinHostPort(portOffset)
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

				// enable TLS if there is a policy and if this is not the HTTP port
				if len(srv.TLSConnPolicies) > 0 &&
					int(listenAddr.StartPort+portOffset) != app.httpPort() {
					// create TLS listener
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

	// finish automatic HTTPS by finally beginning
	// certificate management
	err = app.automaticHTTPSPhase3()
	if err != nil {
		return fmt.Errorf("finalizing automatic HTTPS: %v", err)
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
	if configured < 100 &&
		actual >= configured*100 &&
		actual < (configured+1)*100 {
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
