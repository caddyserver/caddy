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
	"expvar"
	"fmt"
	"io"
	"mime"
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

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"go.uber.org/zap"
)

// TODO: is there a way to make the admin endpoint so that it can be plugged into the HTTP app? see issue #2833

// AdminConfig configures the admin endpoint.
type AdminConfig struct {
	Disabled      bool     `json:"disabled,omitempty"`
	Listen        string   `json:"listen,omitempty"`
	EnforceOrigin bool     `json:"enforce_origin,omitempty"`
	Origins       []string `json:"origins,omitempty"`
}

// listenAddr extracts a singular listen address from ac.Listen,
// returning the network and the address of the listener.
func (admin AdminConfig) listenAddr() (string, string, error) {
	input := admin.Listen
	if input == "" {
		input = DefaultAdminListen
	}
	listenAddr, err := ParseNetworkAddress(input)
	if err != nil {
		return "", "", fmt.Errorf("parsing admin listener address: %v", err)
	}
	if listenAddr.PortRangeSize() != 1 {
		return "", "", fmt.Errorf("admin endpoint must have exactly one address; cannot listen on %v", listenAddr)
	}
	return listenAddr.Network, listenAddr.JoinHostPort(0), nil
}

// newAdminHandler reads admin's config and returns an http.Handler suitable
// for use in an admin endpoint server, which will be listening on listenAddr.
func (admin AdminConfig) newAdminHandler(listenAddr string) adminHandler {
	muxWrap := adminHandler{
		enforceOrigin:  admin.EnforceOrigin,
		allowedOrigins: admin.allowedOrigins(listenAddr),
		mux:            http.NewServeMux(),
	}

	// addRoute just calls muxWrap.mux.Handle after
	// wrapping the handler with error handling
	addRoute := func(pattern string, h AdminHandler) {
		wrapper := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			err := h.ServeHTTP(w, r)
			muxWrap.handleError(w, r, err)
		})
		muxWrap.mux.Handle(pattern, wrapper)
	}

	// register standard config control endpoints
	addRoute("/load", AdminHandlerFunc(handleLoad))
	addRoute("/"+rawConfigKey+"/", AdminHandlerFunc(handleConfig))
	addRoute("/id/", AdminHandlerFunc(handleConfigID))
	addRoute("/stop", AdminHandlerFunc(handleStop))

	// register debugging endpoints
	muxWrap.mux.HandleFunc("/debug/pprof/", pprof.Index)
	muxWrap.mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	muxWrap.mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	muxWrap.mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	muxWrap.mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	muxWrap.mux.Handle("/debug/vars", expvar.Handler())

	// register third-party module endpoints
	for _, m := range GetModules("admin.api") {
		router := m.New().(AdminRouter)
		for _, route := range router.Routes() {
			addRoute(route.Pattern, route.Handler)
		}
	}

	return muxWrap
}

// allowedOrigins returns a list of origins that are allowed.
// If admin.Origins is nil (null), the provided listen address
// will be used as the default origin. If admin.Origins is
// empty, no origins will be allowed, effectively bricking the
// endpoint, but whatever.
func (admin AdminConfig) allowedOrigins(listen string) []string {
	uniqueOrigins := make(map[string]struct{})
	for _, o := range admin.Origins {
		uniqueOrigins[o] = struct{}{}
	}
	if admin.Origins == nil {
		uniqueOrigins[listen] = struct{}{}
	}
	var allowed []string
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
	netw, addr, err := adminConfig.listenAddr()
	if err != nil {
		return err
	}

	handler := adminConfig.newAdminHandler(addr)

	ln, err := Listen(netw, addr)
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

	go adminServer.Serve(ln)

	Log().Named("admin").Info(
		"admin endpoint started",
		zap.String("address", addr),
		zap.Bool("enforce_origin", adminConfig.EnforceOrigin),
		zap.Strings("origins", handler.allowedOrigins),
	)

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
	allowedOrigins []string
	mux            *http.ServeMux
}

// ServeHTTP is the external entry point for API requests.
// It will only be called once per request.
func (h adminHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	Log().Named("admin.api").Info("received request",
		zap.String("method", r.Method),
		zap.String("uri", r.RequestURI),
		zap.String("remote_addr", r.RemoteAddr),
		zap.Reflect("headers", r.Header),
	)
	h.serveHTTP(w, r)
}

// serveHTTP is the internal entry point for API requests. It may
// be called more than once per request, for example if a request
// is rewritten (i.e. internal redirect).
func (h adminHandler) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if h.enforceOrigin {
		// DNS rebinding mitigation
		err := h.checkHost(r)
		if err != nil {
			h.handleError(w, r, err)
			return
		}

		// cross-site mitigation
		origin, err := h.checkOrigin(r)
		if err != nil {
			h.handleError(w, r, err)
			return
		}

		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "OPTIONS, GET, POST, PUT, PATCH, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Cache-Control")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
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
	json.NewEncoder(w).Encode(apiErr)
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

func handleLoad(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		return APIError{
			Code: http.StatusMethodNotAllowed,
			Err:  fmt.Errorf("method not allowed"),
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
	body := buf.Bytes()

	// if the config is formatted other than Caddy's native
	// JSON, we need to adapt it before loading it
	if ctHeader := r.Header.Get("Content-Type"); ctHeader != "" {
		ct, _, err := mime.ParseMediaType(ctHeader)
		if err != nil {
			return APIError{
				Code: http.StatusBadRequest,
				Err:  fmt.Errorf("invalid Content-Type: %v", err),
			}
		}
		if !strings.HasSuffix(ct, "/json") {
			slashIdx := strings.Index(ct, "/")
			if slashIdx < 0 {
				return APIError{
					Code: http.StatusBadRequest,
					Err:  fmt.Errorf("malformed Content-Type"),
				}
			}
			adapterName := ct[slashIdx+1:]
			cfgAdapter := caddyconfig.GetAdapter(adapterName)
			if cfgAdapter == nil {
				return APIError{
					Code: http.StatusBadRequest,
					Err:  fmt.Errorf("unrecognized config adapter '%s'", adapterName),
				}
			}
			result, warnings, err := cfgAdapter.Adapt(body, nil)
			if err != nil {
				return APIError{
					Code: http.StatusBadRequest,
					Err:  fmt.Errorf("adapting config using %s adapter: %v", adapterName, err),
				}
			}
			if len(warnings) > 0 {
				respBody, err := json.Marshal(warnings)
				if err != nil {
					Log().Named("admin.api.load").Error(err.Error())
				}
				w.Write(respBody)
			}
			body = result
		}
	}

	forceReload := r.Header.Get("Cache-Control") == "must-revalidate"

	err = Load(body, forceReload)
	if err != nil {
		return APIError{
			Code: http.StatusBadRequest,
			Err:  fmt.Errorf("loading config: %v", err),
		}
	}

	Log().Named("admin.api").Info("load complete")

	return nil
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
	defer func() {
		Log().Named("admin.api").Info("stopping now, bye!! 👋")
		os.Exit(0)
	}()
	err := handleUnload(w, r)
	if err != nil {
		Log().Named("admin.api").Error("unload error", zap.Error(err))
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
	currentCfgMu.RLock()
	hasCfg := currentCfg != nil
	currentCfgMu.RUnlock()
	if !hasCfg {
		Log().Named("admin.api").Info("nothing to unload")
		return nil
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
					v[part] = append(arr, val)
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
					if arr, ok := v[part].([]interface{}); ok {
						// if the part is an existing list, POST appends to it
						// TODO: Do we ever reach this point, since we handle arrays
						// separately above?
						v[part] = append(arr, val)
					} else {
						// otherwise, it simply sets the value
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
			return fmt.Errorf("invalid path: %s", parts[:i+1])
		}
	}

	return nil
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

// idRegexp is used to match ID fields and their associated values
// in the config. It also matches adjacent commas so that syntax
// can be preserved no matter where in the object the field appears.
// It supports string and most numeric values.
var idRegexp = regexp.MustCompile(`(?m),?\s*"` + idKey + `":\s?(-?[0-9]+(\.[0-9]+)?|(?U)".*")\s*,?`)

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
