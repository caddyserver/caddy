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
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/lucas-clemente/quic-go/http3"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Server describes an HTTP server.
type Server struct {
	// Socket addresses to which to bind listeners. Accepts
	// [network addresses](/docs/conventions#network-addresses)
	// that may include port ranges.
	Listen []string `json:"listen,omitempty"`

	// How long to allow a read from a client's upload. Setting this
	// to a short, non-zero value can mitigate slowloris attacks, but
	// may also affect legitimately slow clients.
	ReadTimeout caddy.Duration `json:"read_timeout,omitempty"`

	// ReadHeaderTimeout is like ReadTimeout but for request headers.
	ReadHeaderTimeout caddy.Duration `json:"read_header_timeout,omitempty"`

	// WriteTimeout is how long to allow a write to a client. Note
	// that setting this to a small value when serving large files
	// may negatively affect legitimately slow clients.
	WriteTimeout caddy.Duration `json:"write_timeout,omitempty"`

	// IdleTimeout is the maximum time to wait for the next request
	// when keep-alives are enabled. If zero, ReadTimeout is used.
	// If both are zero, there is no timeout.
	IdleTimeout caddy.Duration `json:"idle_timeout,omitempty"`

	// MaxHeaderBytes is the maximum size to parse from a client's
	// HTTP request headers.
	MaxHeaderBytes int `json:"max_header_bytes,omitempty"`

	// Routes describes how this server will handle requests.
	// When a request comes in, each route's matchers will
	// be evaluated against the request, and matching routes
	// will be compiled into a middleware chain in the order
	// in which they appear in the list.
	Routes RouteList `json:"routes,omitempty"`

	// Errors is how this server will handle errors returned from any
	// of the handlers in the primary routes. If the primary handler
	// chain returns an error, the error along with its recommended
	// status code are bubbled back up to the HTTP server which
	// executes a separate error route, specified using this property.
	// The error routes work exactly like the normal routes.
	Errors *HTTPErrorConfig `json:"errors,omitempty"`

	// How to handle TLS connections. At least one policy is
	// required to enable HTTPS on this server if automatic
	// HTTPS is disabled or does not apply.
	TLSConnPolicies caddytls.ConnectionPolicies `json:"tls_connection_policies,omitempty"`

	// AutoHTTPS configures or disables automatic HTTPS within this server.
	// HTTPS is enabled automatically and by default when qualifying names
	// are present in a Host matcher and/or when the server is listening
	// only on the HTTPS port.
	AutoHTTPS *AutoHTTPSConfig `json:"automatic_https,omitempty"`

	// MaxRehandles is the maximum number of times to allow a
	// request to be rehandled, to prevent accidental infinite
	// loops. Default: 1.
	MaxRehandles *int `json:"max_rehandles,omitempty"`

	// If true, will require that a request's Host header match
	// the value of the ServerName sent by the client's TLS
	// ClientHello; often a necessary safeguard when using TLS
	// client authentication.
	StrictSNIHost *bool `json:"strict_sni_host,omitempty"`

	// Logs customizes how access logs are handled in this server.
	Logs *ServerLogConfig `json:"logs,omitempty"`

	// Enable experimental HTTP/3 support. Note that HTTP/3 is not a
	// finished standard and has extremely limited client support.
	// This field is not subject to compatibility promises.
	ExperimentalHTTP3 bool `json:"experimental_http3,omitempty"`

	tlsApp       *caddytls.TLS
	logger       *zap.Logger
	accessLogger *zap.Logger
	errorLogger  *zap.Logger

	h3server *http3.Server
}

// ServeHTTP is the entry point for all HTTP requests.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "Caddy")

	if s.h3server != nil {
		err := s.h3server.SetQuicHeaders(w.Header())
		if err != nil {
			s.logger.Error("setting HTTP/3 Alt-Svc header", zap.Error(err))
		}
	}

	// set up the context for the request
	repl := caddy.NewReplacer()
	ctx := context.WithValue(r.Context(), caddy.ReplacerCtxKey, repl)
	ctx = context.WithValue(ctx, ServerCtxKey, s)
	ctx = context.WithValue(ctx, VarsCtxKey, make(map[string]interface{}))
	var url2 url.URL // avoid letting this escape to the heap
	ctx = context.WithValue(ctx, OriginalRequestCtxKey, originalRequest(r, &url2))
	r = r.WithContext(ctx)

	// once the pointer to the request won't change
	// anymore, finish setting up the replacer
	addHTTPVarsToReplacer(repl, r, w)

	loggableReq := LoggableHTTPRequest{r}
	errLog := s.errorLogger.With(
		// encode the request for logging purposes before
		// it enters any handler chain; this is necessary
		// to capture the original request in case it gets
		// modified during handling
		zap.Object("request", loggableReq),
	)

	if s.accessLogger != nil {
		wrec := NewResponseRecorder(w, nil, nil)
		w = wrec
		accLog := s.accessLogger.With(
			// capture the original version of the request
			zap.Object("request", loggableReq),
		)
		start := time.Now()
		defer func() {
			latency := time.Since(start)

			repl.Set("http.response.status", strconv.Itoa(wrec.Status()))
			repl.Set("http.response.size", strconv.Itoa(wrec.Size()))
			repl.Set("http.response.latency", latency.String())

			logger := accLog
			if s.Logs != nil && s.Logs.LoggerNames != nil {
				logger = logger.Named(s.Logs.LoggerNames[r.Host])
			}

			log := logger.Info
			if wrec.Status() >= 400 {
				log = logger.Error
			}

			log("handled request",
				zap.String("common_log", repl.ReplaceAll(CommonLogFormat, "-")),
				zap.Duration("latency", latency),
				zap.Int("size", wrec.Size()),
				zap.Int("status", wrec.Status()),
				zap.Object("resp_headers", LoggableHTTPHeader(wrec.Header())),
			)
		}()
	}

	// guarantee ACME HTTP challenges; handle them
	// separately from any user-defined handlers
	if s.tlsApp.HandleHTTPChallenge(w, r) {
		return
	}

	// build and execute the primary handler chain
	err := s.executeCompositeRoute(w, r, s.Routes)
	if err != nil {
		// prepare the error log
		logger := errLog
		if s.Logs != nil && s.Logs.LoggerNames != nil {
			logger = logger.Named(s.Logs.LoggerNames[r.Host])
		}

		// get the values that will be used to log the error
		errStatus, errMsg, errFields := errLogValues(err)

		// add HTTP error information to request context
		r = s.Errors.WithError(r, err)

		if s.Errors != nil && len(s.Errors.Routes) > 0 {
			// execute user-defined error handling route
			err2 := s.executeCompositeRoute(w, r, s.Errors.Routes)
			if err2 == nil {
				// user's error route handled the error response
				// successfully, so now just log the error
				if errStatus >= 500 {
					logger.Error(errMsg, errFields...)
				}
			} else {
				// well... this is awkward
				errFields = append([]zapcore.Field{
					zap.String("error", err2.Error()),
					zap.Namespace("first_error"),
					zap.String("msg", errMsg),
				}, errFields...)
				logger.Error("error handling handler error", errFields...)
			}
		} else {
			if errStatus >= 500 {
				logger.Error(errMsg, errFields...)
			}
			w.WriteHeader(errStatus)
		}
	}
}

// executeCompositeRoute compiles a composite route from routeList and executes
// it using w and r. This function handles the sentinel ErrRehandle error value,
// which reprocesses requests through the stack again. Any error value returned
// from this function would be an actual error that needs to be handled.
func (s *Server) executeCompositeRoute(w http.ResponseWriter, r *http.Request, routeList RouteList) error {
	maxRehandles := 0
	if s.MaxRehandles != nil {
		maxRehandles = *s.MaxRehandles
	}
	var err error
	for i := -1; i <= maxRehandles; i++ {
		// we started the counter at -1 because we
		// always want to run this at least once

		// the purpose of rehandling is often to give
		// matchers a chance to re-evaluate on the
		// changed version of the request, so compile
		// the handler stack anew in each iteration
		stack := routeList.BuildCompositeRoute(r)
		stack = s.wrapPrimaryRoute(stack)

		// only loop if rehandling is required
		err = stack.ServeHTTP(w, r)
		if err != ErrRehandle {
			break
		}
		if i >= maxRehandles-1 {
			return fmt.Errorf("too many rehandles")
		}
	}
	return err
}

// wrapPrimaryRoute wraps stack (a compiled middleware handler chain)
// in s.enforcementHandler which performs crucial security checks, etc.
func (s *Server) wrapPrimaryRoute(stack Handler) Handler {
	return HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return s.enforcementHandler(w, r, stack)
	})
}

// enforcementHandler is an implicit middleware which performs
// standard checks before executing the HTTP middleware chain.
func (s *Server) enforcementHandler(w http.ResponseWriter, r *http.Request, next Handler) error {
	// enforce strict host matching, which ensures that the SNI
	// value (if any), matches the Host header; essential for
	// servers that rely on TLS ClientAuth sharing a listener
	// with servers that do not; if not enforced, client could
	// bypass by sending benign SNI then restricted Host header
	if s.StrictSNIHost != nil && *s.StrictSNIHost && r.TLS != nil {
		hostname, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			hostname = r.Host // OK; probably lacked port
		}
		if !strings.EqualFold(r.TLS.ServerName, hostname) {
			err := fmt.Errorf("strict host matching: TLS ServerName (%s) and HTTP Host (%s) values differ",
				r.TLS.ServerName, hostname)
			r.Close = true
			return Error(http.StatusForbidden, err)
		}
	}
	return next.ServeHTTP(w, r)
}

// listenersUseAnyPortOtherThan returns true if there are any
// listeners in s that use a port which is not otherPort.
func (s *Server) listenersUseAnyPortOtherThan(otherPort int) bool {
	for _, lnAddr := range s.Listen {
		laddrs, err := caddy.ParseNetworkAddress(lnAddr)
		if err != nil {
			continue
		}
		if uint(otherPort) > laddrs.EndPort || uint(otherPort) < laddrs.StartPort {
			return true
		}
	}
	return false
}

// hasListenerAddress returns true if s has a listener
// at the given address fullAddr. Currently, fullAddr
// must represent exactly one socket address (port
// ranges are not supported)
func (s *Server) hasListenerAddress(fullAddr string) bool {
	laddrs, err := caddy.ParseNetworkAddress(fullAddr)
	if err != nil {
		return false
	}
	if laddrs.PortRangeSize() != 1 {
		return false // TODO: support port ranges
	}

	for _, lnAddr := range s.Listen {
		thisAddrs, err := caddy.ParseNetworkAddress(lnAddr)
		if err != nil {
			continue
		}
		if thisAddrs.Network != laddrs.Network {
			continue
		}

		// host must be the same and port must fall within port range
		if (thisAddrs.Host == laddrs.Host) &&
			(laddrs.StartPort <= thisAddrs.EndPort) &&
			(laddrs.StartPort >= thisAddrs.StartPort) {
			return true
		}
	}
	return false
}

func (s *Server) hasTLSClientAuth() bool {
	for _, cp := range s.TLSConnPolicies {
		if cp.ClientAuthentication != nil && cp.ClientAuthentication.Active() {
			return true
		}
	}
	return false
}

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

// HTTPErrorConfig determines how to handle errors
// from the HTTP handlers.
type HTTPErrorConfig struct {
	// The routes to evaluate after the primary handler
	// chain returns an error. In an error route, extra
	// placeholders are available:
	//
	// {http.error.status_code}
	//     The recommended HTTP status code
	// {http.error.status_text}
	//     The status text associated with the recommended status code
	// {http.error.message}
	//     The error message
	// {http.error.trace}
	//     The origin of the error
	// {http.error.id}
	//     A short, human-conveyable ID for the error
	Routes RouteList `json:"routes,omitempty"`
}

// WithError makes a shallow copy of r to add the error to its
// context, and sets placeholders on the request's replacer
// related to err. It returns the modified request which has
// the error information in its context and replacer. It
// overwrites any existing error values that are stored.
func (*HTTPErrorConfig) WithError(r *http.Request, err error) *http.Request {
	// add the raw error value to the request context
	// so it can be accessed by error handlers
	c := context.WithValue(r.Context(), ErrorCtxKey, err)
	r = r.WithContext(c)

	// add error values to the replacer
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	repl.Set("http.error", err.Error())
	if handlerErr, ok := err.(HandlerError); ok {
		repl.Set("http.error.status_code", strconv.Itoa(handlerErr.StatusCode))
		repl.Set("http.error.status_text", http.StatusText(handlerErr.StatusCode))
		repl.Set("http.error.trace", handlerErr.Trace)
		repl.Set("http.error.id", handlerErr.ID)
	}

	return r
}

// ServerLogConfig describes a server's logging configuration.
type ServerLogConfig struct {
	// LoggerNames maps request hostnames to a custom logger name.
	// For example, a mapping of "example.com" to "example" would
	// cause access logs from requests with a Host of example.com
	// to be emitted by a logger named "http.log.access.example".
	LoggerNames map[string]string `json:"logger_names,omitempty"`
}

// errLogValues inspects err and returns the status code
// to use, the error log message, and any extra fields.
// If err is a HandlerError, the returned values will
// have richer information.
func errLogValues(err error) (status int, msg string, fields []zapcore.Field) {
	if handlerErr, ok := err.(HandlerError); ok {
		status = handlerErr.StatusCode
		if handlerErr.Err == nil {
			msg = err.Error()
		} else {
			msg = handlerErr.Err.Error()
		}
		fields = []zapcore.Field{
			zap.Int("status", handlerErr.StatusCode),
			zap.String("err_id", handlerErr.ID),
			zap.String("err_trace", handlerErr.Trace),
		}
		return
	}
	status = http.StatusInternalServerError
	msg = err.Error()
	return
}

// originalRequest returns a partial, shallow copy of
// req, including: req.Method, deep copy of req.URL
// (into the urlCopy parameter, which should be on the
// stack), req.RequestURI, and req.RemoteAddr. Notably,
// headers are not copied. This function is designed to
// be very fast and efficient, and useful primarily for
// read-only/logging purposes.
func originalRequest(req *http.Request, urlCopy *url.URL) http.Request {
	cloneURL(req.URL, urlCopy)
	return http.Request{
		Method:     req.Method,
		RemoteAddr: req.RemoteAddr,
		RequestURI: req.RequestURI,
		URL:        urlCopy,
	}
}

// cloneURL makes a copy of r.URL and returns a
// new value that doesn't reference the original.
func cloneURL(from, to *url.URL) {
	*to = *from
	if from.User != nil {
		userInfo := new(url.Userinfo)
		*userInfo = *from.User
		to.User = userInfo
	}
}

const (
	// CommonLogFormat is the common log format. https://en.wikipedia.org/wiki/Common_Log_Format
	CommonLogFormat = `{http.request.remote.host} ` + CommonLogEmptyValue + ` {http.authentication.user.id} [{time.now.common_log}] "{http.request.orig_method} {http.request.orig_uri} {http.request.proto}" {http.response.status} {http.response.size}`

	// CommonLogEmptyValue is the common empty log value.
	CommonLogEmptyValue = "-"
)

// Context keys for HTTP request context values.
const (
	// For referencing the server instance
	ServerCtxKey caddy.CtxKey = "server"

	// For the request's variable table
	VarsCtxKey caddy.CtxKey = "vars"

	// For a partial copy of the unmodified request that
	// originally came into the server's entry handler
	OriginalRequestCtxKey caddy.CtxKey = "original_request"
)
