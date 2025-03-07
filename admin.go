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

package caddy

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"hash"
	"io"
	"net"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/cespare/xxhash/v2"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func init() {
	// The hard-coded default `DefaultAdminListen` can be overridden
	// by setting the `CADDY_ADMIN` environment variable.
	// The environment variable may be used by packagers to change
	// the default admin address to something more appropriate for
	// that platform. See #5317 for discussion.
	if env, exists := os.LookupEnv("CADDY_ADMIN"); exists {
		DefaultAdminListen = env
	}
}

// AdminConfig configures Caddy's API endpoint, which is used
// to manage Caddy while it is running.
type AdminConfig struct {
	// If true, the admin endpoint will be completely disabled.
	// Note that this makes any runtime changes to the config
	// impossible, since the interface to do so is through the
	// admin endpoint.
	Disabled bool `json:"disabled,omitempty"`

	// The address to which the admin endpoint's listener should
	// bind itself. Can be any single network address that can be
	// parsed by Caddy. Accepts placeholders.
	// Default: the value of the `CADDY_ADMIN` environment variable,
	// or `localhost:2019` otherwise.
	//
	// Remember: When changing this value through a config reload,
	// be sure to use the `--address` CLI flag to specify the current
	// admin address if the currently-running admin endpoint is not
	// the default address.
	Listen string `json:"listen,omitempty"`

	// If true, CORS headers will be emitted, and requests to the
	// API will be rejected if their `Host` and `Origin` headers
	// do not match the expected value(s). Use `origins` to
	// customize which origins/hosts are allowed. If `origins` is
	// not set, the listen address is the only value allowed by
	// default. Enforced only on local (plaintext) endpoint.
	EnforceOrigin bool `json:"enforce_origin,omitempty"`

	// The list of allowed origins/hosts for API requests. Only needed
	// if accessing the admin endpoint from a host different from the
	// socket's network interface or if `enforce_origin` is true. If not
	// set, the listener address will be the default value. If set but
	// empty, no origins will be allowed. Enforced only on local
	// (plaintext) endpoint.
	Origins []string `json:"origins,omitempty"`

	// Options pertaining to configuration management.
	Config *ConfigSettings `json:"config,omitempty"`

	// Options that establish this server's identity. Identity refers to
	// credentials which can be used to uniquely identify and authenticate
	// this server instance. This is required if remote administration is
	// enabled (but does not require remote administration to be enabled).
	// Default: no identity management.
	Identity *IdentityConfig `json:"identity,omitempty"`

	// Options pertaining to remote administration. By default, remote
	// administration is disabled. If enabled, identity management must
	// also be configured, as that is how the endpoint is secured.
	// See the neighboring "identity" object.
	//
	// EXPERIMENTAL: This feature is subject to change.
	Remote *RemoteAdmin `json:"remote,omitempty"`

	// Holds onto the routers so that we can later provision them
	// if they require provisioning.
	routers []AdminRouter
}

// ConfigSettings configures the management of configuration.
type ConfigSettings struct {
	// Whether to keep a copy of the active config on disk. Default is true.
	// Note that "pulled" dynamic configs (using the neighboring "load" module)
	// are not persisted; only configs that are pushed to Caddy get persisted.
	Persist *bool `json:"persist,omitempty"`

	// Loads a new configuration. This is helpful if your configs are
	// managed elsewhere and you want Caddy to pull its config dynamically
	// when it starts. The pulled config completely replaces the current
	// one, just like any other config load. It is an error if a pulled
	// config is configured to pull another config without a load_delay,
	// as this creates a tight loop.
	//
	// EXPERIMENTAL: Subject to change.
	LoadRaw json.RawMessage `json:"load,omitempty" caddy:"namespace=caddy.config_loaders inline_key=module"`

	// The duration after which to load config. If set, config will be pulled
	// from the config loader after this duration. A delay is required if a
	// dynamically-loaded config is configured to load yet another config. To
	// load configs on a regular interval, ensure this value is set the same
	// on all loaded configs; it can also be variable if needed, and to stop
	// the loop, simply remove dynamic config loading from the next-loaded
	// config.
	//
	// EXPERIMENTAL: Subject to change.
	LoadDelay Duration `json:"load_delay,omitempty"`
}

// IdentityConfig configures management of this server's identity. An identity
// consists of credentials that uniquely verify this instance; for example,
// TLS certificates (public + private key pairs).
type IdentityConfig struct {
	// List of names or IP addresses which refer to this server.
	// Certificates will be obtained for these identifiers so
	// secure TLS connections can be made using them.
	Identifiers []string `json:"identifiers,omitempty"`

	// Issuers that can provide this admin endpoint its identity
	// certificate(s). Default: ACME issuers configured for
	// ZeroSSL and Let's Encrypt. Be sure to change this if you
	// require credentials for private identifiers.
	IssuersRaw []json.RawMessage `json:"issuers,omitempty" caddy:"namespace=tls.issuance inline_key=module"`

	issuers []certmagic.Issuer
}

// RemoteAdmin enables and configures remote administration. If enabled,
// a secure listener enforcing mutual TLS authentication will be started
// on a different port from the standard plaintext admin server.
//
// This endpoint is secured using identity management, which must be
// configured separately (because identity management does not depend
// on remote administration). See the admin/identity config struct.
//
// EXPERIMENTAL: Subject to change.
type RemoteAdmin struct {
	// The address on which to start the secure listener. Accepts placeholders.
	// Default: :2021
	Listen string `json:"listen,omitempty"`

	// List of access controls for this secure admin endpoint.
	// This configures TLS mutual authentication (i.e. authorized
	// client certificates), but also application-layer permissions
	// like which paths and methods each identity is authorized for.
	AccessControl []*AdminAccess `json:"access_control,omitempty"`
}

// AdminAccess specifies what permissions an identity or group
// of identities are granted.
type AdminAccess struct {
	// Base64-encoded DER certificates containing public keys to accept.
	// (The contents of PEM certificate blocks are base64-encoded DER.)
	// Any of these public keys can appear in any part of a verified chain.
	PublicKeys []string `json:"public_keys,omitempty"`

	// Limits what the associated identities are allowed to do.
	// If unspecified, all permissions are granted.
	Permissions []AdminPermissions `json:"permissions,omitempty"`

	publicKeys []crypto.PublicKey
}

// AdminPermissions specifies what kinds of requests are allowed
// to be made to the admin endpoint.
type AdminPermissions struct {
	// The API paths allowed. Paths are simple prefix matches.
	// Any subpath of the specified paths will be allowed.
	Paths []string `json:"paths,omitempty"`

	// The HTTP methods allowed for the given paths.
	Methods []string `json:"methods,omitempty"`
}

// newAdminHandler reads admin's config and returns an http.Handler suitable
// for use in an admin endpoint server, which will be listening on listenAddr.
func (admin *AdminConfig) newAdminHandler(addr NetworkAddress, remote bool, _ Context) adminHandler {
	muxWrap := adminHandler{mux: http.NewServeMux()}

	// secure the local or remote endpoint respectively
	if remote {
		muxWrap.remoteControl = admin.Remote
	} else {
		muxWrap.enforceHost = !addr.isWildcardInterface()
		muxWrap.allowedOrigins = admin.allowedOrigins(addr)
		muxWrap.enforceOrigin = admin.EnforceOrigin
	}

	addRouteWithMetrics := func(pattern string, handlerLabel string, h http.Handler) {
		labels := prometheus.Labels{"path": pattern, "handler": handlerLabel}
		h = instrumentHandlerCounter(
			adminMetrics.requestCount.MustCurryWith(labels),
			h,
		)
		muxWrap.mux.Handle(pattern, h)
	}
	// addRoute just calls muxWrap.mux.Handle after
	// wrapping the handler with error handling
	addRoute := func(pattern string, handlerLabel string, h AdminHandler) {
		wrapper := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			err := h.ServeHTTP(w, r)
			if err != nil {
				labels := prometheus.Labels{
					"path":    pattern,
					"handler": handlerLabel,
					"method":  strings.ToUpper(r.Method),
				}
				adminMetrics.requestErrors.With(labels).Inc()
			}
			muxWrap.handleError(w, r, err)
		})
		addRouteWithMetrics(pattern, handlerLabel, wrapper)
	}

	const handlerLabel = "admin"

	// register standard config control endpoints
	addRoute("/"+rawConfigKey+"/", handlerLabel, AdminHandlerFunc(handleConfig))
	addRoute("/id/", handlerLabel, AdminHandlerFunc(handleConfigID))
	addRoute("/stop", handlerLabel, AdminHandlerFunc(handleStop))

	// register debugging endpoints
	addRouteWithMetrics("/debug/pprof/", handlerLabel, http.HandlerFunc(pprof.Index))
	addRouteWithMetrics("/debug/pprof/cmdline", handlerLabel, http.HandlerFunc(pprof.Cmdline))
	addRouteWithMetrics("/debug/pprof/profile", handlerLabel, http.HandlerFunc(pprof.Profile))
	addRouteWithMetrics("/debug/pprof/symbol", handlerLabel, http.HandlerFunc(pprof.Symbol))
	addRouteWithMetrics("/debug/pprof/trace", handlerLabel, http.HandlerFunc(pprof.Trace))
	addRouteWithMetrics("/debug/vars", handlerLabel, expvar.Handler())

	// register third-party module endpoints
	for _, m := range GetModules("admin.api") {
		router := m.New().(AdminRouter)
		for _, route := range router.Routes() {
			addRoute(route.Pattern, handlerLabel, route.Handler)
		}
		admin.routers = append(admin.routers, router)
	}

	return muxWrap
}

// provisionAdminRouters provisions all the router modules
// in the admin.api namespace that need provisioning.
func (admin *AdminConfig) provisionAdminRouters(ctx Context) error {
	for _, router := range admin.routers {
		provisioner, ok := router.(Provisioner)
		if !ok {
			continue
		}

		err := provisioner.Provision(ctx)
		if err != nil {
			return err
		}
	}

	// We no longer need the routers once provisioned, allow for GC
	admin.routers = nil

	return nil
}

// allowedOrigins returns a list of origins that are allowed.
// If admin.Origins is nil (null), the provided listen address
// will be used as the default origin. If admin.Origins is
// empty, no origins will be allowed, effectively bricking the
// endpoint for non-unix-socket endpoints, but whatever.
func (admin AdminConfig) allowedOrigins(addr NetworkAddress) []*url.URL {
	uniqueOrigins := make(map[string]struct{})
	for _, o := range admin.Origins {
		uniqueOrigins[o] = struct{}{}
	}
	if admin.Origins == nil {
		if addr.isLoopback() {
			if addr.IsUnixNetwork() || addr.IsFdNetwork() {
				// RFC 2616, Section 14.26:
				// "A client MUST include a Host header field in all HTTP/1.1 request
				// messages. If the requested URI does not include an Internet host
				// name for the service being requested, then the Host header field MUST
				// be given with an empty value."
				//
				// UPDATE July 2023: Go broke this by patching a minor security bug in 1.20.6.
				// Understandable, but frustrating. See:
				// https://github.com/golang/go/issues/60374
				// See also the discussion here:
				// https://github.com/golang/go/issues/61431
				//
				// We can no longer conform to RFC 2616 Section 14.26 from either Go or curl
				// in purity. (Curl allowed no host between 7.40 and 7.50, but now requires a
				// bogus host; see https://superuser.com/a/925610.) If we disable Host/Origin
				// security checks, the infosec community assures me that it is secure to do
				// so, because:
				// 1) Browsers do not allow access to unix sockets
				// 2) DNS is irrelevant to unix sockets
				//
				// I am not quite ready to trust either of those external factors, so instead
				// of disabling Host/Origin checks, we now allow specific Host values when
				// accessing the admin endpoint over unix sockets. I definitely don't trust
				// DNS (e.g. I don't trust 'localhost' to always resolve to the local host),
				// and IP shouldn't even be used, but if it is for some reason, I think we can
				// at least be reasonably assured that 127.0.0.1 and ::1 route to the local
				// machine, meaning that a hypothetical browser origin would have to be on the
				// local machine as well.
				uniqueOrigins[""] = struct{}{}
				uniqueOrigins["127.0.0.1"] = struct{}{}
				uniqueOrigins["::1"] = struct{}{}
			} else {
				uniqueOrigins[net.JoinHostPort("localhost", addr.port())] = struct{}{}
				uniqueOrigins[net.JoinHostPort("::1", addr.port())] = struct{}{}
				uniqueOrigins[net.JoinHostPort("127.0.0.1", addr.port())] = struct{}{}
			}
		}
		if !addr.IsUnixNetwork() && !addr.IsFdNetwork() {
			uniqueOrigins[addr.JoinHostPort(0)] = struct{}{}
		}
	}
	allowed := make([]*url.URL, 0, len(uniqueOrigins))
	for originStr := range uniqueOrigins {
		var origin *url.URL
		if strings.Contains(originStr, "://") {
			var err error
			origin, err = url.Parse(originStr)
			if err != nil {
				continue
			}
			origin.Path = ""
			origin.RawPath = ""
			origin.Fragment = ""
			origin.RawFragment = ""
			origin.RawQuery = ""
		} else {
			origin = &url.URL{Host: originStr}
		}
		allowed = append(allowed, origin)
	}
	return allowed
}

// replaceLocalAdminServer replaces the running local admin server
// according to the relevant configuration in cfg. If no configuration
// for the admin endpoint exists in cfg, a default one is used, so
// that there is always an admin server (unless it is explicitly
// configured to be disabled).
// Critically note that some elements and functionality of the context
// may not be ready, e.g. storage. Tread carefully.
func replaceLocalAdminServer(cfg *Config, ctx Context) error {
	// always* be sure to close down the old admin endpoint
	// as gracefully as possible, even if the new one is
	// disabled -- careful to use reference to the current
	// (old) admin endpoint since it will be different
	// when the function returns
	// (* except if the new one fails to start)
	oldAdminServer := localAdminServer
	var err error
	defer func() {
		// do the shutdown asynchronously so that any
		// current API request gets a response; this
		// goroutine may last a few seconds
		if oldAdminServer != nil && err == nil {
			go func(oldAdminServer *http.Server) {
				err := stopAdminServer(oldAdminServer)
				if err != nil {
					Log().Named("admin").Error("stopping current admin endpoint", zap.Error(err))
				}
			}(oldAdminServer)
		}
	}()

	// set a default if admin wasn't otherwise configured
	if cfg.Admin == nil {
		cfg.Admin = &AdminConfig{
			Listen: DefaultAdminListen,
		}
	}

	// if new admin endpoint is to be disabled, we're done
	if cfg.Admin.Disabled {
		Log().Named("admin").Warn("admin endpoint disabled")
		return nil
	}

	// extract a singular listener address
	addr, err := parseAdminListenAddr(cfg.Admin.Listen, DefaultAdminListen)
	if err != nil {
		return err
	}

	handler := cfg.Admin.newAdminHandler(addr, false, ctx)

	ln, err := addr.Listen(context.TODO(), 0, net.ListenConfig{})
	if err != nil {
		return err
	}

	serverMu.Lock()
	localAdminServer = &http.Server{
		Addr:              addr.String(), // for logging purposes only
		Handler:           handler,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1024 * 64,
	}
	serverMu.Unlock()

	adminLogger := Log().Named("admin")
	go func() {
		serverMu.Lock()
		server := localAdminServer
		serverMu.Unlock()
		if err := server.Serve(ln.(net.Listener)); !errors.Is(err, http.ErrServerClosed) {
			adminLogger.Error("admin server shutdown for unknown reason", zap.Error(err))
		}
	}()

	adminLogger.Info("admin endpoint started",
		zap.String("address", addr.String()),
		zap.Bool("enforce_origin", cfg.Admin.EnforceOrigin),
		zap.Array("origins", loggableURLArray(handler.allowedOrigins)))

	if !handler.enforceHost {
		adminLogger.Warn("admin endpoint on open interface; host checking disabled",
			zap.String("address", addr.String()))
	}

	return nil
}

// manageIdentity sets up automated identity management for this server.
func manageIdentity(ctx Context, cfg *Config) error {
	if cfg == nil || cfg.Admin == nil || cfg.Admin.Identity == nil {
		return nil
	}

	// set default issuers; this is pretty hacky because we can't
	// import the caddytls package -- but it works
	if cfg.Admin.Identity.IssuersRaw == nil {
		cfg.Admin.Identity.IssuersRaw = []json.RawMessage{
			json.RawMessage(`{"module": "acme"}`),
		}
	}

	// load and provision issuer modules
	if cfg.Admin.Identity.IssuersRaw != nil {
		val, err := ctx.LoadModule(cfg.Admin.Identity, "IssuersRaw")
		if err != nil {
			return fmt.Errorf("loading identity issuer modules: %s", err)
		}
		for _, issVal := range val.([]any) {
			cfg.Admin.Identity.issuers = append(cfg.Admin.Identity.issuers, issVal.(certmagic.Issuer))
		}
	}

	// we'll make a new cache when we make the CertMagic config, so stop any previous cache
	if identityCertCache != nil {
		identityCertCache.Stop()
	}

	logger := Log().Named("admin.identity")
	cmCfg := cfg.Admin.Identity.certmagicConfig(logger, true)

	// issuers have circular dependencies with the configs because,
	// as explained in the caddytls package, they need access to the
	// correct storage and cache to solve ACME challenges
	for _, issuer := range cfg.Admin.Identity.issuers {
		// avoid import cycle with caddytls package, so manually duplicate the interface here, yuck
		if annoying, ok := issuer.(interface{ SetConfig(cfg *certmagic.Config) }); ok {
			annoying.SetConfig(cmCfg)
		}
	}

	// obtain and renew server identity certificate(s)
	return cmCfg.ManageAsync(ctx, cfg.Admin.Identity.Identifiers)
}

// replaceRemoteAdminServer replaces the running remote admin server
// according to the relevant configuration in cfg. It stops any previous
// remote admin server and only starts a new one if configured.
func replaceRemoteAdminServer(ctx Context, cfg *Config) error {
	if cfg == nil {
		return nil
	}

	remoteLogger := Log().Named("admin.remote")

	oldAdminServer := remoteAdminServer
	defer func() {
		if oldAdminServer != nil {
			go func(oldAdminServer *http.Server) {
				err := stopAdminServer(oldAdminServer)
				if err != nil {
					Log().Named("admin").Error("stopping current secure admin endpoint", zap.Error(err))
				}
			}(oldAdminServer)
		}
	}()

	if cfg.Admin == nil || cfg.Admin.Remote == nil {
		return nil
	}

	addr, err := parseAdminListenAddr(cfg.Admin.Remote.Listen, DefaultRemoteAdminListen)
	if err != nil {
		return err
	}

	// make the HTTP handler but disable Host/Origin enforcement
	// because we are using TLS authentication instead
	handler := cfg.Admin.newAdminHandler(addr, true, ctx)

	// create client certificate pool for TLS mutual auth, and extract public keys
	// so that we can enforce access controls at the application layer
	clientCertPool := x509.NewCertPool()
	for i, accessControl := range cfg.Admin.Remote.AccessControl {
		for j, certBase64 := range accessControl.PublicKeys {
			cert, err := decodeBase64DERCert(certBase64)
			if err != nil {
				return fmt.Errorf("access control %d public key %d: parsing base64 certificate DER: %v", i, j, err)
			}
			accessControl.publicKeys = append(accessControl.publicKeys, cert.PublicKey)
			clientCertPool.AddCert(cert)
		}
	}

	// create TLS config that will enforce mutual authentication
	if identityCertCache == nil {
		return fmt.Errorf("cannot enable remote admin without a certificate cache; configure identity management to initialize a certificate cache")
	}
	cmCfg := cfg.Admin.Identity.certmagicConfig(remoteLogger, false)
	tlsConfig := cmCfg.TLSConfig()
	tlsConfig.NextProtos = nil // this server does not solve ACME challenges
	tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	tlsConfig.ClientCAs = clientCertPool

	// convert logger to stdlib so it can be used by HTTP server
	serverLogger, err := zap.NewStdLogAt(remoteLogger, zap.DebugLevel)
	if err != nil {
		return err
	}

	serverMu.Lock()
	// create secure HTTP server
	remoteAdminServer = &http.Server{
		Addr:              addr.String(), // for logging purposes only
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1024 * 64,
		ErrorLog:          serverLogger,
	}
	serverMu.Unlock()

	// start listener
	lnAny, err := addr.Listen(ctx, 0, net.ListenConfig{})
	if err != nil {
		return err
	}
	ln := lnAny.(net.Listener)
	ln = tls.NewListener(ln, tlsConfig)

	go func() {
		serverMu.Lock()
		server := remoteAdminServer
		serverMu.Unlock()
		if err := server.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
			remoteLogger.Error("admin remote server shutdown for unknown reason", zap.Error(err))
		}
	}()

	remoteLogger.Info("secure admin remote control endpoint started",
		zap.String("address", addr.String()))

	return nil
}

func (ident *IdentityConfig) certmagicConfig(logger *zap.Logger, makeCache bool) *certmagic.Config {
	var cmCfg *certmagic.Config
	if ident == nil {
		// user might not have configured identity; that's OK, we can still make a
		// certmagic config, although it'll be mostly useless for remote management
		ident = new(IdentityConfig)
	}
	template := certmagic.Config{
		Storage: DefaultStorage, // do not act as part of a cluster (this is for the server's local identity)
		Logger:  logger,
		Issuers: ident.issuers,
	}
	if makeCache {
		identityCertCache = certmagic.NewCache(certmagic.CacheOptions{
			GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
				return cmCfg, nil
			},
			Logger: logger.Named("cache"),
		})
	}
	cmCfg = certmagic.New(identityCertCache, template)
	return cmCfg
}

// IdentityCredentials returns this instance's configured, managed identity credentials
// that can be used in TLS client authentication.
func (ctx Context) IdentityCredentials(logger *zap.Logger) ([]tls.Certificate, error) {
	if ctx.cfg == nil || ctx.cfg.Admin == nil || ctx.cfg.Admin.Identity == nil {
		return nil, fmt.Errorf("no server identity configured")
	}
	ident := ctx.cfg.Admin.Identity
	if len(ident.Identifiers) == 0 {
		return nil, fmt.Errorf("no identifiers configured")
	}
	if logger == nil {
		logger = Log()
	}
	magic := ident.certmagicConfig(logger, false)
	return magic.ClientCredentials(ctx, ident.Identifiers)
}

// enforceAccessControls enforces application-layer access controls for r based on remote.
// It expects that the TLS server has already established at least one verified chain of
// trust, and then looks for a matching, authorized public key that is allowed to access
// the defined path(s) using the defined method(s).
func (remote RemoteAdmin) enforceAccessControls(r *http.Request) error {
	for _, chain := range r.TLS.VerifiedChains {
		for _, peerCert := range chain {
			for _, adminAccess := range remote.AccessControl {
				for _, allowedKey := range adminAccess.publicKeys {
					// see if we found a matching public key; the TLS server already verified the chain
					// so we know the client possesses the associated private key; this handy interface
					// doesn't appear to be defined anywhere in the std lib, but was implemented here:
					// https://github.com/golang/go/commit/b5f2c0f50297fa5cd14af668ddd7fd923626cf8c
					comparer, ok := peerCert.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
					if !ok || !comparer.Equal(allowedKey) {
						continue
					}

					// key recognized; make sure its HTTP request is permitted
					for _, accessPerm := range adminAccess.Permissions {
						// verify method
						methodFound := accessPerm.Methods == nil || slices.Contains(accessPerm.Methods, r.Method)
						if !methodFound {
							return APIError{
								HTTPStatus: http.StatusForbidden,
								Message:    "not authorized to use this method",
							}
						}

						// verify path
						pathFound := accessPerm.Paths == nil
						for _, allowedPath := range accessPerm.Paths {
							if strings.HasPrefix(r.URL.Path, allowedPath) {
								pathFound = true
								break
							}
						}
						if !pathFound {
							return APIError{
								HTTPStatus: http.StatusForbidden,
								Message:    "not authorized to access this path",
							}
						}
					}

					// public key authorized, method and path allowed
					return nil
				}
			}
		}
	}

	// in theory, this should never happen; with an unverified chain, the TLS server
	// should not accept the connection in the first place, and the acceptable cert
	// pool is configured using the same list of public keys we verify against
	return APIError{
		HTTPStatus: http.StatusUnauthorized,
		Message:    "client identity not authorized",
	}
}

func stopAdminServer(srv *http.Server) error {
	if srv == nil {
		return fmt.Errorf("no admin server")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := srv.Shutdown(ctx)
	if err != nil {
		return fmt.Errorf("shutting down admin server: %v", err)
	}
	Log().Named("admin").Info("stopped previous server", zap.String("address", srv.Addr))
	return nil
}

// AdminRouter is a type which can return routes for the admin API.
type AdminRouter interface {
	Routes() []AdminRoute
}

// AdminRoute represents a route for the admin endpoint.
type AdminRoute struct {
	Pattern string
	Handler AdminHandler
}

type adminHandler struct {
	mux *http.ServeMux

	// security for local/plaintext endpoint
	enforceOrigin  bool
	enforceHost    bool
	allowedOrigins []*url.URL

	// security for remote/encrypted endpoint
	remoteControl *RemoteAdmin
}

// ServeHTTP is the external entry point for API requests.
// It will only be called once per request.
func (h adminHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ip, port, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
		port = ""
	}
	log := Log().Named("admin.api").With(
		zap.String("method", r.Method),
		zap.String("host", r.Host),
		zap.String("uri", r.RequestURI),
		zap.String("remote_ip", ip),
		zap.String("remote_port", port),
		zap.Reflect("headers", r.Header),
	)
	if r.TLS != nil {
		log = log.With(
			zap.Bool("secure", true),
			zap.Int("verified_chains", len(r.TLS.VerifiedChains)),
		)
	}
	if r.RequestURI == "/metrics" {
		log.Debug("received request")
	} else {
		log.Info("received request")
	}
	h.serveHTTP(w, r)
}

// serveHTTP is the internal entry point for API requests. It may
// be called more than once per request, for example if a request
// is rewritten (i.e. internal redirect).
func (h adminHandler) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if h.remoteControl != nil {
		// enforce access controls on secure endpoint
		if err := h.remoteControl.enforceAccessControls(r); err != nil {
			h.handleError(w, r, err)
			return
		}
	}

	if strings.Contains(r.Header.Get("Upgrade"), "websocket") {
		// I've never been able demonstrate a vulnerability myself, but apparently
		// WebSocket connections originating from browsers aren't subject to CORS
		// restrictions, so we'll just be on the safe side
		h.handleError(w, r, fmt.Errorf("websocket connections aren't allowed"))
		return
	}

	if h.enforceHost {
		// DNS rebinding mitigation
		err := h.checkHost(r)
		if err != nil {
			h.handleError(w, r, err)
			return
		}
	}

	if h.enforceOrigin {
		// cross-site mitigation
		origin, err := h.checkOrigin(r)
		if err != nil {
			h.handleError(w, r, err)
			return
		}

		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "OPTIONS, GET, POST, PUT, PATCH, DELETE")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Cache-Control")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}

	h.mux.ServeHTTP(w, r)
}

func (h adminHandler) handleError(w http.ResponseWriter, r *http.Request, err error) {
	if err == nil {
		return
	}
	if err == errInternalRedir {
		h.serveHTTP(w, r)
		return
	}

	apiErr, ok := err.(APIError)
	if !ok {
		apiErr = APIError{
			HTTPStatus: http.StatusInternalServerError,
			Err:        err,
		}
	}
	if apiErr.HTTPStatus == 0 {
		apiErr.HTTPStatus = http.StatusInternalServerError
	}
	if apiErr.Message == "" && apiErr.Err != nil {
		apiErr.Message = apiErr.Err.Error()
	}

	Log().Named("admin.api").Error("request error",
		zap.Error(err),
		zap.Int("status_code", apiErr.HTTPStatus),
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(apiErr.HTTPStatus)
	encErr := json.NewEncoder(w).Encode(apiErr)
	if encErr != nil {
		Log().Named("admin.api").Error("failed to encode error response", zap.Error(encErr))
	}
}

// checkHost returns a handler that wraps next such that
// it will only be called if the request's Host header matches
// a trustworthy/expected value. This helps to mitigate DNS
// rebinding attacks.
func (h adminHandler) checkHost(r *http.Request) error {
	allowed := slices.ContainsFunc(h.allowedOrigins, func(u *url.URL) bool {
		return r.Host == u.Host
	})
	if !allowed {
		return APIError{
			HTTPStatus: http.StatusForbidden,
			Err:        fmt.Errorf("host not allowed: %s", r.Host),
		}
	}
	return nil
}

// checkOrigin ensures that the Origin header, if
// set, matches the intended target; prevents arbitrary
// sites from issuing requests to our listener. It
// returns the origin that was obtained from r.
func (h adminHandler) checkOrigin(r *http.Request) (string, error) {
	originStr, origin := h.getOrigin(r)
	if origin == nil {
		return "", APIError{
			HTTPStatus: http.StatusForbidden,
			Err:        fmt.Errorf("required Origin header is missing or invalid"),
		}
	}
	if !h.originAllowed(origin) {
		return "", APIError{
			HTTPStatus: http.StatusForbidden,
			Err:        fmt.Errorf("client is not allowed to access from origin '%s'", originStr),
		}
	}
	return origin.String(), nil
}

func (h adminHandler) getOrigin(r *http.Request) (string, *url.URL) {
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = r.Header.Get("Referer")
	}
	originURL, err := url.Parse(origin)
	if err != nil {
		return origin, nil
	}
	originURL.Path = ""
	originURL.RawPath = ""
	originURL.Fragment = ""
	originURL.RawFragment = ""
	originURL.RawQuery = ""
	return origin, originURL
}

func (h adminHandler) originAllowed(origin *url.URL) bool {
	for _, allowedOrigin := range h.allowedOrigins {
		if allowedOrigin.Scheme != "" && origin.Scheme != allowedOrigin.Scheme {
			continue
		}
		if origin.Host == allowedOrigin.Host {
			return true
		}
	}
	return false
}

// etagHasher returns a the hasher we used on the config to both
// produce and verify ETags.
func etagHasher() hash.Hash { return xxhash.New() }

// makeEtag returns an Etag header value (including quotes) for
// the given config path and hash of contents at that path.
func makeEtag(path string, hash hash.Hash) string {
	return fmt.Sprintf(`"%s %x"`, path, hash.Sum(nil))
}

// This buffer pool is used to keep buffers for
// reading the config file during eTag header generation
var bufferPool = sync.Pool{
	New: func() any {
		return new(bytes.Buffer)
	},
}

func handleConfig(w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		hash := etagHasher()

		// Read the config into a buffer instead of writing directly to
		// the response writer, as we want to set the ETag as the header,
		// not the trailer.
		buf := bufferPool.Get().(*bytes.Buffer)
		buf.Reset()
		defer bufferPool.Put(buf)

		configWriter := io.MultiWriter(buf, hash)
		err := readConfig(r.URL.Path, configWriter)
		if err != nil {
			return APIError{HTTPStatus: http.StatusBadRequest, Err: err}
		}

		// we could consider setting up a sync.Pool for the summed
		// hashes to reduce GC pressure.
		w.Header().Set("Etag", makeEtag(r.URL.Path, hash))
		_, err = w.Write(buf.Bytes())
		if err != nil {
			return APIError{HTTPStatus: http.StatusInternalServerError, Err: err}
		}

		return nil

	case http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete:

		// DELETE does not use a body, but the others do
		var body []byte
		if r.Method != http.MethodDelete {
			if ct := r.Header.Get("Content-Type"); !strings.Contains(ct, "/json") {
				return APIError{
					HTTPStatus: http.StatusBadRequest,
					Err:        fmt.Errorf("unacceptable content-type: %v; 'application/json' required", ct),
				}
			}

			buf := bufPool.Get().(*bytes.Buffer)
			buf.Reset()
			defer bufPool.Put(buf)

			_, err := io.Copy(buf, r.Body)
			if err != nil {
				return APIError{
					HTTPStatus: http.StatusBadRequest,
					Err:        fmt.Errorf("reading request body: %v", err),
				}
			}
			body = buf.Bytes()
		}

		forceReload := r.Header.Get("Cache-Control") == "must-revalidate"

		err := changeConfig(r.Method, r.URL.Path, body, r.Header.Get("If-Match"), forceReload)
		if err != nil && !errors.Is(err, errSameConfig) {
			return err
		}

	default:
		return APIError{
			HTTPStatus: http.StatusMethodNotAllowed,
			Err:        fmt.Errorf("method %s not allowed", r.Method),
		}
	}

	return nil
}

func handleConfigID(w http.ResponseWriter, r *http.Request) error {
	idPath := r.URL.Path

	parts := strings.Split(idPath, "/")
	if len(parts) < 3 || parts[2] == "" {
		return APIError{
			HTTPStatus: http.StatusBadRequest,
			Err:        fmt.Errorf("request path is missing object ID"),
		}
	}
	if parts[0] != "" || parts[1] != "id" {
		return APIError{
			HTTPStatus: http.StatusBadRequest,
			Err:        fmt.Errorf("malformed object path"),
		}
	}
	id := parts[2]

	// map the ID to the expanded path
	rawCfgMu.RLock()
	expanded, ok := rawCfgIndex[id]
	rawCfgMu.RUnlock()
	if !ok {
		return APIError{
			HTTPStatus: http.StatusNotFound,
			Err:        fmt.Errorf("unknown object ID '%s'", id),
		}
	}

	// piece the full URL path back together
	parts = append([]string{expanded}, parts[3:]...)
	r.URL.Path = path.Join(parts...)

	return errInternalRedir
}

func handleStop(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		return APIError{
			HTTPStatus: http.StatusMethodNotAllowed,
			Err:        fmt.Errorf("method not allowed"),
		}
	}

	exitProcess(context.Background(), Log().Named("admin.api"))
	return nil
}

// unsyncedConfigAccess traverses into the current config and performs
// the operation at path according to method, using body and out as
// needed. This is a low-level, unsynchronized function; most callers
// will want to use changeConfig or readConfig instead. This requires a
// read or write lock on currentCtxMu, depending on method (GET needs
// only a read lock; all others need a write lock).
func unsyncedConfigAccess(method, path string, body []byte, out io.Writer) error {
	var err error
	var val any

	// if there is a request body, decode it into the
	// variable that will be set in the config according
	// to method and path
	if len(body) > 0 {
		err = json.Unmarshal(body, &val)
		if err != nil {
			return fmt.Errorf("decoding request body: %v", err)
		}
	}

	enc := json.NewEncoder(out)

	cleanPath := strings.Trim(path, "/")
	if cleanPath == "" {
		return fmt.Errorf("no traversable path")
	}

	parts := strings.Split(cleanPath, "/")
	if len(parts) == 0 {
		return fmt.Errorf("path missing")
	}

	// A path that ends with "..." implies:
	// 1) the part before it is an array
	// 2) the payload is an array
	// and means that the user wants to expand the elements
	// in the payload array and append each one into the
	// destination array, like so:
	//     array = append(array, elems...)
	// This special case is handled below.
	ellipses := parts[len(parts)-1] == "..."
	if ellipses {
		parts = parts[:len(parts)-1]
	}

	var ptr any = rawCfg

traverseLoop:
	for i, part := range parts {
		switch v := ptr.(type) {
		case map[string]any:
			// if the next part enters a slice, and the slice is our destination,
			// handle it specially (because appending to the slice copies the slice
			// header, which does not replace the original one like we want)
			if arr, ok := v[part].([]any); ok && i == len(parts)-2 {
				var idx int
				if method != http.MethodPost {
					idxStr := parts[len(parts)-1]
					idx, err = strconv.Atoi(idxStr)
					if err != nil {
						return fmt.Errorf("[%s] invalid array index '%s': %v",
							path, idxStr, err)
					}
					if idx < 0 || (method != http.MethodPut && idx >= len(arr)) || idx > len(arr) {
						return fmt.Errorf("[%s] array index out of bounds: %s", path, idxStr)
					}
				}

				switch method {
				case http.MethodGet:
					err = enc.Encode(arr[idx])
					if err != nil {
						return fmt.Errorf("encoding config: %v", err)
					}
				case http.MethodPost:
					if ellipses {
						valArray, ok := val.([]any)
						if !ok {
							return fmt.Errorf("final element is not an array")
						}
						v[part] = append(arr, valArray...)
					} else {
						v[part] = append(arr, val)
					}
				case http.MethodPut:
					// avoid creation of new slice and a second copy (see
					// https://github.com/golang/go/wiki/SliceTricks#insert)
					arr = append(arr, nil)
					copy(arr[idx+1:], arr[idx:])
					arr[idx] = val
					v[part] = arr
				case http.MethodPatch:
					arr[idx] = val
				case http.MethodDelete:
					v[part] = append(arr[:idx], arr[idx+1:]...)
				default:
					return fmt.Errorf("unrecognized method %s", method)
				}
				break traverseLoop
			}

			if i == len(parts)-1 {
				switch method {
				case http.MethodGet:
					err = enc.Encode(v[part])
					if err != nil {
						return fmt.Errorf("encoding config: %v", err)
					}
				case http.MethodPost:
					// if the part is an existing list, POST appends to
					// it, otherwise it just sets or creates the value
					if arr, ok := v[part].([]any); ok {
						if ellipses {
							valArray, ok := val.([]any)
							if !ok {
								return fmt.Errorf("final element is not an array")
							}
							v[part] = append(arr, valArray...)
						} else {
							v[part] = append(arr, val)
						}
					} else {
						v[part] = val
					}
				case http.MethodPut:
					if _, ok := v[part]; ok {
						return APIError{
							HTTPStatus: http.StatusConflict,
							Err:        fmt.Errorf("[%s] key already exists: %s", path, part),
						}
					}
					v[part] = val
				case http.MethodPatch:
					if _, ok := v[part]; !ok {
						return APIError{
							HTTPStatus: http.StatusNotFound,
							Err:        fmt.Errorf("[%s] key does not exist: %s", path, part),
						}
					}
					v[part] = val
				case http.MethodDelete:
					if _, ok := v[part]; !ok {
						return APIError{
							HTTPStatus: http.StatusNotFound,
							Err:        fmt.Errorf("[%s] key does not exist: %s", path, part),
						}
					}
					delete(v, part)
				default:
					return fmt.Errorf("unrecognized method %s", method)
				}
			} else {
				// if we are "PUTting" a new resource, the key(s) in its path
				// might not exist yet; that's OK but we need to make them as
				// we go, while we still have a pointer from the level above
				if v[part] == nil && method == http.MethodPut {
					v[part] = make(map[string]any)
				}
				ptr = v[part]
			}

		case []any:
			partInt, err := strconv.Atoi(part)
			if err != nil {
				return fmt.Errorf("[/%s] invalid array index '%s': %v",
					strings.Join(parts[:i+1], "/"), part, err)
			}
			if partInt < 0 || partInt >= len(v) {
				return fmt.Errorf("[/%s] array index out of bounds: %s",
					strings.Join(parts[:i+1], "/"), part)
			}
			ptr = v[partInt]

		default:
			return fmt.Errorf("invalid traversal path at: %s", strings.Join(parts[:i+1], "/"))
		}
	}

	return nil
}

// RemoveMetaFields removes meta fields like "@id" from a JSON message
// by using a simple regular expression. (An alternate way to do this
// would be to delete them from the raw, map[string]any
// representation as they are indexed, then iterate the index we made
// and add them back after encoding as JSON, but this is simpler.)
func RemoveMetaFields(rawJSON []byte) []byte {
	return idRegexp.ReplaceAllFunc(rawJSON, func(in []byte) []byte {
		// matches with a comma on both sides (when "@id" property is
		// not the first or last in the object) need to keep exactly
		// one comma for correct JSON syntax
		comma := []byte{','}
		if bytes.HasPrefix(in, comma) && bytes.HasSuffix(in, comma) {
			return comma
		}
		return []byte{}
	})
}

// AdminHandler is like http.Handler except ServeHTTP may return an error.
//
// If any handler encounters an error, it should be returned for proper
// handling.
type AdminHandler interface {
	ServeHTTP(http.ResponseWriter, *http.Request) error
}

// AdminHandlerFunc is a convenience type like http.HandlerFunc.
type AdminHandlerFunc func(http.ResponseWriter, *http.Request) error

// ServeHTTP implements the Handler interface.
func (f AdminHandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	return f(w, r)
}

// APIError is a structured error that every API
// handler should return for consistency in logging
// and client responses. If Message is unset, then
// Err.Error() will be serialized in its place.
type APIError struct {
	HTTPStatus int    `json:"-"`
	Err        error  `json:"-"`
	Message    string `json:"error"`
}

func (e APIError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return e.Message
}

// parseAdminListenAddr extracts a singular listen address from either addr
// or defaultAddr, returning the network and the address of the listener.
func parseAdminListenAddr(addr string, defaultAddr string) (NetworkAddress, error) {
	input, err := NewReplacer().ReplaceOrErr(addr, true, true)
	if err != nil {
		return NetworkAddress{}, fmt.Errorf("replacing listen address: %v", err)
	}
	if input == "" {
		input = defaultAddr
	}
	listenAddr, err := ParseNetworkAddress(input)
	if err != nil {
		return NetworkAddress{}, fmt.Errorf("parsing listener address: %v", err)
	}
	if listenAddr.PortRangeSize() != 1 {
		return NetworkAddress{}, fmt.Errorf("must be exactly one listener address; cannot listen on: %s", listenAddr)
	}
	return listenAddr, nil
}

// decodeBase64DERCert base64-decodes, then DER-decodes, certStr.
func decodeBase64DERCert(certStr string) (*x509.Certificate, error) {
	derBytes, err := base64.StdEncoding.DecodeString(certStr)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(derBytes)
}

type loggableURLArray []*url.URL

func (ua loggableURLArray) MarshalLogArray(enc zapcore.ArrayEncoder) error {
	if ua == nil {
		return nil
	}
	for _, u := range ua {
		enc.AppendString(u.String())
	}
	return nil
}

var (
	// DefaultAdminListen is the address for the local admin
	// listener, if none is specified at startup.
	DefaultAdminListen = "localhost:2019"

	// DefaultRemoteAdminListen is the address for the remote
	// (TLS-authenticated) admin listener, if enabled and not
	// specified otherwise.
	DefaultRemoteAdminListen = ":2021"
)

// PIDFile writes a pidfile to the file at filename. It
// will get deleted before the process gracefully exits.
func PIDFile(filename string) error {
	pid := []byte(strconv.Itoa(os.Getpid()) + "\n")
	err := os.WriteFile(filename, pid, 0o600)
	if err != nil {
		return err
	}
	pidfile = filename
	return nil
}

// idRegexp is used to match ID fields and their associated values
// in the config. It also matches adjacent commas so that syntax
// can be preserved no matter where in the object the field appears.
// It supports string and most numeric values.
var idRegexp = regexp.MustCompile(`(?m),?\s*"` + idKey + `"\s*:\s*(-?[0-9]+(\.[0-9]+)?|(?U)".*")\s*,?`)

// pidfile is the name of the pidfile, if any.
var pidfile string

// errInternalRedir indicates an internal redirect
// and is useful when admin API handlers rewrite
// the request; in that case, authentication and
// authorization needs to happen again for the
// rewritten request.
var errInternalRedir = fmt.Errorf("internal redirect; re-authorization required")

const (
	rawConfigKey = "config"
	idKey        = "@id"
)

var bufPool = sync.Pool{
	New: func() any {
		return new(bytes.Buffer)
	},
}

// keep a reference to admin endpoint singletons while they're active
var (
	serverMu                            sync.Mutex
	localAdminServer, remoteAdminServer *http.Server
	identityCertCache                   *certmagic.Cache
)
