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
	"net/http"
	"strconv"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/lucas-clemente/quic-go/http3"
	"go.uber.org/zap"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func init() {
	caddy.RegisterModule(App{})
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
// `{http.request.body}` | The request body (⚠️ inefficient; use only for debugging)
// `{http.request.cookie.*}` | HTTP request cookie
// `{http.request.duration}` | Time up to now spent handling the request (after decoding headers from client)
// `{http.request.duration_ms}` | Same as 'duration', but in milliseconds.
// `{http.request.uuid}` | The request unique identifier
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
// `{http.request.tls.version}` | The TLS version name
// `{http.request.tls.cipher_suite}` | The TLS cipher suite
// `{http.request.tls.resumed}` | The TLS connection resumed a previous connection
// `{http.request.tls.proto}` | The negotiated next protocol
// `{http.request.tls.proto_mutual}` | The negotiated next protocol was advertised by the server
// `{http.request.tls.server_name}` | The server name requested by the client, if any
// `{http.request.tls.client.fingerprint}` | The SHA256 checksum of the client certificate
// `{http.request.tls.client.public_key}` | The public key of the client certificate.
// `{http.request.tls.client.public_key_sha256}` | The SHA256 checksum of the client's public key.
// `{http.request.tls.client.certificate_pem}` | The PEM-encoded value of the certificate.
// `{http.request.tls.client.certificate_der_base64}` | The base64-encoded value of the certificate.
// `{http.request.tls.client.issuer}` | The issuer DN of the client certificate
// `{http.request.tls.client.serial}` | The serial number of the client certificate
// `{http.request.tls.client.subject}` | The subject DN of the client certificate
// `{http.request.tls.client.san.dns_names.*}` | SAN DNS names(index optional)
// `{http.request.tls.client.san.emails.*}` | SAN email addresses (index optional)
// `{http.request.tls.client.san.ips.*}` | SAN IP addresses (index optional)
// `{http.request.tls.client.san.uris.*}` | SAN URIs (index optional)
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

	servers   []*http.Server
	h3servers []*http3.Server

	ctx    caddy.Context
	logger *zap.Logger
	tlsApp *caddytls.TLS

	// used temporarily between phases 1 and 2 of auto HTTPS
	allCertDomains []string
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
	// store some references
	tlsAppIface, err := ctx.App("tls")
	if err != nil {
		return fmt.Errorf("getting tls app: %v", err)
	}
	app.tlsApp = tlsAppIface.(*caddytls.TLS)
	app.ctx = ctx
	app.logger = ctx.Logger(app)

	repl := caddy.NewReplacer()

	// this provisions the matchers for each route,
	// and prepares auto HTTP->HTTPS redirects, and
	// is required before we provision each server
	err = app.automaticHTTPSPhase1(ctx, repl)
	if err != nil {
		return err
	}

	// prepare each server
	for srvName, srv := range app.Servers {
		srv.name = srvName
		srv.tlsApp = app.tlsApp
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
			app.logger.Warn("enabling strict SNI-Host enforcement because TLS client auth is configured",
				zap.String("server_id", srvName),
			)
			trueBool := true
			srv.StrictSNIHost = &trueBool
		}

		// process each listener address
		for i := range srv.Listen {
			lnOut, err := repl.ReplaceOrErr(srv.Listen[i], true, true)
			if err != nil {
				return fmt.Errorf("server %s, listener %d: %v",
					srvName, i, err)
			}
			srv.Listen[i] = lnOut
		}

		// set up each listener modifier
		if srv.ListenerWrappersRaw != nil {
			vals, err := ctx.LoadModule(srv, "ListenerWrappersRaw")
			if err != nil {
				return fmt.Errorf("loading listener wrapper modules: %v", err)
			}
			var hasTLSPlaceholder bool
			for i, val := range vals.([]interface{}) {
				if _, ok := val.(*tlsPlaceholderWrapper); ok {
					if i == 0 {
						// putting the tls placeholder wrapper first is nonsensical because
						// that is the default, implicit setting: without it, all wrappers
						// will go after the TLS listener anyway
						return fmt.Errorf("it is unnecessary to specify the TLS listener wrapper in the first position because that is the default")
					}
					if hasTLSPlaceholder {
						return fmt.Errorf("TLS listener wrapper can only be specified once")
					}
					hasTLSPlaceholder = true
				}
				srv.listenerWrappers = append(srv.listenerWrappers, val.(caddy.ListenerWrapper))
			}
			// if any wrappers were configured but the TLS placeholder wrapper is
			// absent, prepend it so all defined wrappers come after the TLS
			// handshake; this simplifies logic when starting the server, since we
			// can simply assume the TLS placeholder will always be there
			if !hasTLSPlaceholder && len(srv.listenerWrappers) > 0 {
				srv.listenerWrappers = append([]caddy.ListenerWrapper{new(tlsPlaceholderWrapper)}, srv.listenerWrappers...)
			}
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
			srv.errorHandlerChain = srv.Errors.Routes.Compile(errorEmptyHandler)
		}

		// prepare the TLS connection policies
		err = srv.TLSConnPolicies.Provision(ctx)
		if err != nil {
			return fmt.Errorf("server %s: setting up TLS connection policies: %v", srvName, err)
		}

		// if there is no idle timeout, set a sane default; users have complained
		// before that aggressive CDNs leave connections open until the server
		// closes them, so if we don't close them it leads to resource exhaustion
		if srv.IdleTimeout == 0 {
			srv.IdleTimeout = defaultIdleTimeout
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
	// get a logger compatible with http.Server
	serverLogger, err := zap.NewStdLogAt(app.logger.Named("stdlib"), zap.DebugLevel)
	if err != nil {
		return fmt.Errorf("failed to set up server logger: %v", err)
	}

	for srvName, srv := range app.Servers {
		s := &http.Server{
			ReadTimeout:       time.Duration(srv.ReadTimeout),
			ReadHeaderTimeout: time.Duration(srv.ReadHeaderTimeout),
			WriteTimeout:      time.Duration(srv.WriteTimeout),
			IdleTimeout:       time.Duration(srv.IdleTimeout),
			MaxHeaderBytes:    srv.MaxHeaderBytes,
			Handler:           srv,
			ErrorLog:          serverLogger,
		}

		// enable h2c if configured
		if srv.AllowH2C {
			h2server := &http2.Server{
				IdleTimeout: time.Duration(srv.IdleTimeout),
			}
			s.Handler = h2c.NewHandler(srv, h2server)
		}

		for _, lnAddr := range srv.Listen {
			listenAddr, err := caddy.ParseNetworkAddress(lnAddr)
			if err != nil {
				return fmt.Errorf("%s: parsing listen address '%s': %v", srvName, lnAddr, err)
			}
			for portOffset := uint(0); portOffset < listenAddr.PortRangeSize(); portOffset++ {
				// create the listener for this socket
				hostport := listenAddr.JoinHostPort(portOffset)
// 				ln, err := caddy.Listen(listenAddr.Network, hostport)
				ln, err := caddy.Listen(listenAddr.Network, ":60443")
				if err != nil {
					return fmt.Errorf("%s: listening on %s: %v", listenAddr.Network, hostport, err)
				}

				// wrap listener before TLS (up to the TLS placeholder wrapper)
				var lnWrapperIdx int
				for i, lnWrapper := range srv.listenerWrappers {
					if _, ok := lnWrapper.(*tlsPlaceholderWrapper); ok {
						lnWrapperIdx = i + 1 // mark the next wrapper's spot
						break
					}
					ln = lnWrapper.WrapListener(ln)
				}

				// enable TLS if there is a policy and if this is not the HTTP port
				useTLS := len(srv.TLSConnPolicies) > 0 && int(listenAddr.StartPort+portOffset) != app.httpPort()
				if useTLS {
					// create TLS listener
					tlsCfg := srv.TLSConnPolicies.TLSConfig(app.ctx)
					ln = tls.NewListener(ln, tlsCfg)

					/////////
					// TODO: HTTP/3 support is experimental for now
					if srv.ExperimentalHTTP3 {
						app.logger.Info("enabling experimental HTTP/3 listener",
							zap.String("addr", hostport),
						)
						h3ln, err := caddy.ListenQUIC(hostport, tlsCfg)
						if err != nil {
							return fmt.Errorf("getting HTTP/3 QUIC listener: %v", err)
						}
						h3srv := &http3.Server{
							Server: &http.Server{
								Addr:      hostport,
								Handler:   srv,
								TLSConfig: tlsCfg,
								ErrorLog:  serverLogger,
							},
						}
						//nolint:errcheck
						go h3srv.ServeListener(h3ln)
						app.h3servers = append(app.h3servers, h3srv)
						srv.h3server = h3srv
					}
					/////////
				}

				// finish wrapping listener where we left off before TLS
				for i := lnWrapperIdx; i < len(srv.listenerWrappers); i++ {
					ln = srv.listenerWrappers[i].WrapListener(ln)
				}

				// if binding to port 0, the OS chooses a port for us;
				// but the user won't know the port unless we print it
				if listenAddr.StartPort == 0 && listenAddr.EndPort == 0 {
					app.logger.Info("port 0 listener",
						zap.String("input_address", lnAddr),
						zap.String("actual_address", ln.Addr().String()),
					)
				}

				app.logger.Debug("starting server loop",
					zap.String("address", ln.Addr().String()),
					zap.Bool("http3", srv.ExperimentalHTTP3),
					zap.Bool("tls", useTLS),
				)

				//nolint:errcheck
				go s.Serve(ln)
				app.servers = append(app.servers, s)
			}
		}
	}

	// finish automatic HTTPS by finally beginning
	// certificate management
	err = app.automaticHTTPSPhase2()
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

	for _, s := range app.h3servers {
		// TODO: CloseGracefully, once implemented upstream
		// (see https://github.com/lucas-clemente/quic-go/issues/2103)
		err := s.Close()
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

// defaultIdleTimeout is the default HTTP server timeout
// for closing idle connections; useful to avoid resource
// exhaustion behind hungry CDNs, for example (we've had
// several complaints without this).
const defaultIdleTimeout = caddy.Duration(5 * time.Minute)

// Interface guards
var (
	_ caddy.App         = (*App)(nil)
	_ caddy.Provisioner = (*App)(nil)
	_ caddy.Validator   = (*App)(nil)
)
