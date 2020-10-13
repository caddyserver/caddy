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
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

// TODO: is there a way to make the admin endpoint so that it can be plugged into the HTTP app? see issue #2833

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
	// parsed by Caddy. Default: localhost:2019
	Listen string `json:"listen,omitempty"`

	// If true, CORS headers will be emitted, and requests to the
	// API will be rejected if their `Host` and `Origin` headers
	// do not match the expected value(s). Use `origins` to
	// customize which origins/hosts are allowed.If `origins` is
	// not set, the listen address is the only value allowed by
	// default.
	EnforceOrigin bool `json:"enforce_origin,omitempty"`

	// The list of allowed origins/hosts for API requests. Only needed
	// if accessing the admin endpoint from a host different from the
	// socket's network interface or if `enforce_origin` is true. If not
	// set, the listener address will be the default value. If set but
	// empty, no origins will be allowed.
	Origins []string `json:"origins,omitempty"`

	// Options related to configuration management.
	Config *ConfigSettings `json:"config,omitempty"`
}

// ConfigSettings configures the, uh, configuration... and
// management thereof.
type ConfigSettings struct {
	// Whether to keep a copy of the active config on disk. Default is true.
	Persist *bool `json:"persist,omitempty"`
}

// listenAddr extracts a singular listen address from ac.Listen,
// returning the network and the address of the listener.
func (admin AdminConfig) listenAddr() (NetworkAddress, error) {
	input := admin.Listen
	if input == "" {
		input = DefaultAdminListen
	}
	listenAddr, err := ParseNetworkAddress(input)
	if err != nil {
		return NetworkAddress{}, fmt.Errorf("parsing admin listener address: %v", err)
	}
	if listenAddr.PortRangeSize() != 1 {
		return NetworkAddress{}, fmt.Errorf("admin endpoint must have exactly one address; cannot listen on %v", listenAddr)
	}
	return listenAddr, nil
}

// newAdminHandler reads admin's config and returns an http.Handler suitable
// for use in an admin endpoint server, which will be listening on listenAddr.
func (admin AdminConfig) newAdminHandler(addr NetworkAddress) adminHandler {
	muxWrap := adminHandler{
		enforceOrigin:  admin.EnforceOrigin,
		enforceHost:    !addr.isWildcardInterface(),
		allowedOrigins: admin.allowedOrigins(addr),
		mux:            http.NewServeMux(),
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
		handlerLabel := m.ID.Name()
		for _, route := range router.Routes() {
			addRoute(route.Pattern, handlerLabel, route.Handler)
		}
	}

	return muxWrap
}

// allowedOrigins returns a list of origins that are allowed.
// If admin.Origins is nil (null), the provided listen address
// will be used as the default origin. If admin.Origins is
// empty, no origins will be allowed, effectively bricking the
// endpoint for non-unix-socket endpoints, but whatever.
func (admin AdminConfig) allowedOrigins(addr NetworkAddress) []string {
	uniqueOrigins := make(map[string]struct{})
	for _, o := range admin.Origins {
		uniqueOrigins[o] = struct{}{}
	}
	if admin.Origins == nil {
		if addr.isLoopback() {
			if addr.IsUnixNetwork() {
				// RFC 2616, Section 14.26:
				// "A client MUST include a Host header field in all HTTP/1.1 request
				// messages. If the requested URI does not include an Internet host
				// name for the service being requested, then the Host header field MUST
				// be given with an empty value."
				uniqueOrigins[""] = struct{}{}
			} else {
				uniqueOrigins[net.JoinHostPort("localhost", addr.port())] = struct{}{}
				uniqueOrigins[net.JoinHostPort("::1", addr.port())] = struct{}{}
				uniqueOrigins[net.JoinHostPort("127.0.0.1", addr.port())] = struct{}{}
			}
		}
		if !addr.IsUnixNetwork() {
			uniqueOrigins[addr.JoinHostPort(0)] = struct{}{}
		}
	}
	allowed := make([]string, 0, len(uniqueOrigins))
	for origin := range uniqueOrigins {
		allowed = append(allowed, origin)
	}
	return allowed
}

// replaceAdmin replaces the running admin server according
// to the relevant configuration in cfg. If no configuration
// for the admin endpoint exists in cfg, a default one is
// used, so that there is always an admin server (unless it
// is explicitly configured to be disabled).
func replaceAdmin(cfg *Config) error {
	// always be sure to close down the old admin endpoint
	// as gracefully as possible, even if the new one is
	// disabled -- careful to use reference to the current
	// (old) admin endpoint since it will be different
	// when the function returns
	oldAdminServer := adminServer
	defer func() {
		// do the shutdown asynchronously so that any
		// current API request gets a response; this
		// goroutine may last a few seconds
		if oldAdminServer != nil {
			go func(oldAdminServer *http.Server) {
				err := stopAdminServer(oldAdminServer)
				if err != nil {
					Log().Named("admin").Error("stopping current admin endpoint", zap.Error(err))
				}
			}(oldAdminServer)
		}
	}()

	// always get a valid admin config
	adminConfig := DefaultAdminConfig
	if cfg != nil && cfg.Admin != nil {
		adminConfig = cfg.Admin
	}

	// if new admin endpoint is to be disabled, we're done
	if adminConfig.Disabled {
		Log().Named("admin").Warn("admin endpoint disabled")
		return nil
	}

	// extract a singular listener address
	addr, err := adminConfig.listenAddr()
	if err != nil {
		return err
	}

	handler := adminConfig.newAdminHandler(addr)

	ln, err := Listen(addr.Network, addr.JoinHostPort(0))
	if err != nil {
		return err
	}

	adminServer = &http.Server{
		Handler:           handler,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1024 * 64,
	}

	adminLogger := Log().Named("admin")
	go func() {
		if err := adminServer.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
			adminLogger.Error("admin server shutdown for unknown reason", zap.Error(err))
		}
	}()

	adminLogger.Info("admin endpoint started",
		zap.String("address", addr.String()),
		zap.Bool("enforce_origin", adminConfig.EnforceOrigin),
		zap.Strings("origins", handler.allowedOrigins))

	if !handler.enforceHost {
		adminLogger.Warn("admin endpoint on open interface; host checking disabled",
			zap.String("address", addr.String()))
	}

	return nil
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
	Log().Named("admin").Info("stopped previous server")
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
	enforceOrigin  bool
	enforceHost    bool
	allowedOrigins []string
	mux            *http.ServeMux
}

// ServeHTTP is the external entry point for API requests.
// It will only be called once per request.
func (h adminHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log := Log().Named("admin.api").With(
		zap.String("method", r.Method),
		zap.String("host", r.Host),
		zap.String("uri", r.RequestURI),
		zap.String("remote_addr", r.RemoteAddr),
		zap.Reflect("headers", r.Header),
	)
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

	// TODO: authentication & authorization, if configured

	h.mux.ServeHTTP(w, r)
}

func (h adminHandler) handleError(w http.ResponseWriter, r *http.Request, err error) {
	if err == nil {
		return
	}
	if err == ErrInternalRedir {
		h.serveHTTP(w, r)
		return
	}

	apiErr, ok := err.(APIError)
	if !ok {
		apiErr = APIError{
			Code: http.StatusInternalServerError,
			Err:  err,
		}
	}
	if apiErr.Code == 0 {
		apiErr.Code = http.StatusInternalServerError
	}
	if apiErr.Message == "" && apiErr.Err != nil {
		apiErr.Message = apiErr.Err.Error()
	}

	Log().Named("admin.api").Error("request error",
		zap.Error(err),
		zap.Int("status_code", apiErr.Code),
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(apiErr.Code)
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
	var allowed bool
	for _, allowedHost := range h.allowedOrigins {
		if r.Host == allowedHost {
			allowed = true
			break
		}
	}
	if !allowed {
		return APIError{
			Code: http.StatusForbidden,
			Err:  fmt.Errorf("host not allowed: %s", r.Host),
		}
	}
	return nil
}

// checkOrigin ensures that the Origin header, if
// set, matches the intended target; prevents arbitrary
// sites from issuing requests to our listener. It
// returns the origin that was obtained from r.
func (h adminHandler) checkOrigin(r *http.Request) (string, error) {
	origin := h.getOriginHost(r)
	if origin == "" {
		return origin, APIError{
			Code: http.StatusForbidden,
			Err:  fmt.Errorf("missing required Origin header"),
		}
	}
	if !h.originAllowed(origin) {
		return origin, APIError{
			Code: http.StatusForbidden,
			Err:  fmt.Errorf("client is not allowed to access from origin %s", origin),
		}
	}
	return origin, nil
}

func (h adminHandler) getOriginHost(r *http.Request) string {
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = r.Header.Get("Referer")
	}
	originURL, err := url.Parse(origin)
	if err == nil && originURL.Host != "" {
		origin = originURL.Host
	}
	return origin
}

func (h adminHandler) originAllowed(origin string) bool {
	for _, allowedOrigin := range h.allowedOrigins {
		originCopy := origin
		if !strings.Contains(allowedOrigin, "://") {
			// no scheme specified, so allow both
			originCopy = strings.TrimPrefix(originCopy, "http://")
			originCopy = strings.TrimPrefix(originCopy, "https://")
		}
		if originCopy == allowedOrigin {
			return true
		}
	}
	return false
}

func handleConfig(w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")

		err := readConfig(r.URL.Path, w)
		if err != nil {
			return APIError{Code: http.StatusBadRequest, Err: err}
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
					Code: http.StatusBadRequest,
					Err:  fmt.Errorf("unacceptable content-type: %v; 'application/json' required", ct),
				}
			}

			buf := bufPool.Get().(*bytes.Buffer)
			buf.Reset()
			defer bufPool.Put(buf)

			_, err := io.Copy(buf, r.Body)
			if err != nil {
				return APIError{
					Code: http.StatusBadRequest,
					Err:  fmt.Errorf("reading request body: %v", err),
				}
			}
			body = buf.Bytes()
		}

		forceReload := r.Header.Get("Cache-Control") == "must-revalidate"

		err := changeConfig(r.Method, r.URL.Path, body, forceReload)
		if err != nil {
			return err
		}

	default:
		return APIError{
			Code: http.StatusMethodNotAllowed,
			Err:  fmt.Errorf("method %s not allowed", r.Method),
		}
	}

	return nil
}

func handleConfigID(w http.ResponseWriter, r *http.Request) error {
	idPath := r.URL.Path

	parts := strings.Split(idPath, "/")
	if len(parts) < 3 || parts[2] == "" {
		return fmt.Errorf("request path is missing object ID")
	}
	if parts[0] != "" || parts[1] != "id" {
		return fmt.Errorf("malformed object path")
	}
	id := parts[2]

	// map the ID to the expanded path
	currentCfgMu.RLock()
	expanded, ok := rawCfgIndex[id]
	defer currentCfgMu.RUnlock()
	if !ok {
		return fmt.Errorf("unknown object ID '%s'", id)
	}

	// piece the full URL path back together
	parts = append([]string{expanded}, parts[3:]...)
	r.URL.Path = path.Join(parts...)

	return ErrInternalRedir
}

func handleStop(w http.ResponseWriter, r *http.Request) error {
	err := handleUnload(w, r)
	if err != nil {
		Log().Named("admin.api").Error("unload error", zap.Error(err))
	}
	if adminServer != nil {
		// use goroutine so that we can finish responding to API request
		go func() {
			err := stopAdminServer(adminServer)
			var exitCode int
			if err != nil {
				exitCode = ExitCodeFailedQuit
				Log().Named("admin.api").Error("failed to stop admin server gracefully", zap.Error(err))
			}
			Log().Named("admin.api").Info("stopping now, bye!! 👋")
			os.Exit(exitCode)
		}()
	}
	return nil
}

// handleUnload stops the current configuration that is running.
// Note that doing this can also be accomplished with DELETE /config/
// but we leave this function because handleStop uses it.
func handleUnload(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		return APIError{
			Code: http.StatusMethodNotAllowed,
			Err:  fmt.Errorf("method not allowed"),
		}
	}
	Log().Named("admin.api").Info("unloading")
	if err := stopAndCleanup(); err != nil {
		Log().Named("admin.api").Error("error unloading", zap.Error(err))
	} else {
		Log().Named("admin.api").Info("unloading completed")
	}
	return nil
}

// unsyncedConfigAccess traverses into the current config and performs
// the operation at path according to method, using body and out as
// needed. This is a low-level, unsynchronized function; most callers
// will want to use changeConfig or readConfig instead. This requires a
// read or write lock on currentCfgMu, depending on method (GET needs
// only a read lock; all others need a write lock).
func unsyncedConfigAccess(method, path string, body []byte, out io.Writer) error {
	var err error
	var val interface{}

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

	var ptr interface{} = rawCfg

traverseLoop:
	for i, part := range parts {
		switch v := ptr.(type) {
		case map[string]interface{}:
			// if the next part enters a slice, and the slice is our destination,
			// handle it specially (because appending to the slice copies the slice
			// header, which does not replace the original one like we want)
			if arr, ok := v[part].([]interface{}); ok && i == len(parts)-2 {
				var idx int
				if method != http.MethodPost {
					idxStr := parts[len(parts)-1]
					idx, err = strconv.Atoi(idxStr)
					if err != nil {
						return fmt.Errorf("[%s] invalid array index '%s': %v",
							path, idxStr, err)
					}
					if idx < 0 || idx >= len(arr) {
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
						valArray, ok := val.([]interface{})
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
					if arr, ok := v[part].([]interface{}); ok {
						if ellipses {
							valArray, ok := val.([]interface{})
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
						return fmt.Errorf("[%s] key already exists: %s", path, part)
					}
					v[part] = val
				case http.MethodPatch:
					if _, ok := v[part]; !ok {
						return fmt.Errorf("[%s] key does not exist: %s", path, part)
					}
					v[part] = val
				case http.MethodDelete:
					delete(v, part)
				default:
					return fmt.Errorf("unrecognized method %s", method)
				}
			} else {
				// if we are "PUTting" a new resource, the key(s) in its path
				// might not exist yet; that's OK but we need to make them as
				// we go, while we still have a pointer from the level above
				if v[part] == nil && method == http.MethodPut {
					v[part] = make(map[string]interface{})
				}
				ptr = v[part]
			}

		case []interface{}:
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
// would be to delete them from the raw, map[string]interface{}
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
	Code    int    `json:"-"`
	Err     error  `json:"-"`
	Message string `json:"error"`
}

func (e APIError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return e.Message
}

var (
	// DefaultAdminListen is the address for the admin
	// listener, if none is specified at startup.
	DefaultAdminListen = "localhost:2019"

	// ErrInternalRedir indicates an internal redirect
	// and is useful when admin API handlers rewrite
	// the request; in that case, authentication and
	// authorization needs to happen again for the
	// rewritten request.
	ErrInternalRedir = fmt.Errorf("internal redirect; re-authorization required")

	// DefaultAdminConfig is the default configuration
	// for the administration endpoint.
	DefaultAdminConfig = &AdminConfig{
		Listen: DefaultAdminListen,
	}
)

// PIDFile writes a pidfile to the file at filename. It
// will get deleted before the process gracefully exits.
func PIDFile(filename string) error {
	pid := []byte(strconv.Itoa(os.Getpid()) + "\n")
	err := ioutil.WriteFile(filename, pid, 0600)
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

const (
	rawConfigKey = "config"
	idKey        = "@id"
)

var bufPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

var adminServer *http.Server
