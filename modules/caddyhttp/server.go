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
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyevents"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/caddyserver/certmagic"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Server describes an HTTP server.
type Server struct {
	activeRequests int64 // accessed atomically

	// Socket addresses to which to bind listeners. Accepts
	// [network addresses](/docs/conventions#network-addresses)
	// that may include port ranges. Listener addresses must
	// be unique; they cannot be repeated across all defined
	// servers.
	Listen []string `json:"listen,omitempty"`

	// A list of listener wrapper modules, which can modify the behavior
	// of the base listener. They are applied in the given order.
	ListenerWrappersRaw []json.RawMessage `json:"listener_wrappers,omitempty" caddy:"namespace=caddy.listeners inline_key=wrapper"`

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
	// when keep-alives are enabled. If zero, a default timeout of
	// 5m is applied to help avoid resource exhaustion.
	IdleTimeout caddy.Duration `json:"idle_timeout,omitempty"`

	// KeepAliveInterval is the interval at which TCP keepalive packets
	// are sent to keep the connection alive at the TCP layer when no other
	// data is being transmitted. The default is 15s.
	KeepAliveInterval caddy.Duration `json:"keepalive_interval,omitempty"`

	// MaxHeaderBytes is the maximum size to parse from a client's
	// HTTP request headers.
	MaxHeaderBytes int `json:"max_header_bytes,omitempty"`

	// Routes describes how this server will handle requests.
	// Routes are executed sequentially. First a route's matchers
	// are evaluated, then its grouping. If it matches and has
	// not been mutually-excluded by its grouping, then its
	// handlers are executed sequentially. The sequence of invoked
	// handlers comprises a compiled middleware chain that flows
	// from each matching route and its handlers to the next.
	//
	// By default, all unrouted requests receive a 200 OK response
	// to indicate the server is working.
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

	// If true, will require that a request's Host header match
	// the value of the ServerName sent by the client's TLS
	// ClientHello; often a necessary safeguard when using TLS
	// client authentication.
	StrictSNIHost *bool `json:"strict_sni_host,omitempty"`

	// A module which provides a source of IP ranges, from which
	// requests should be trusted. By default, no proxies are
	// trusted.
	//
	// On its own, this configuration will not do anything,
	// but it can be used as a default set of ranges for
	// handlers or matchers in routes to pick up, instead
	// of needing to configure each of them. See the
	// `reverse_proxy` handler for example, which uses this
	// to trust sensitive incoming `X-Forwarded-*` headers.
	TrustedProxiesRaw json.RawMessage `json:"trusted_proxies,omitempty" caddy:"namespace=http.ip_sources inline_key=source"`

	// Enables access logging and configures how access logs are handled
	// in this server. To minimally enable access logs, simply set this
	// to a non-null, empty struct.
	Logs *ServerLogConfig `json:"logs,omitempty"`

	// Protocols specifies which HTTP protocols to enable.
	// Supported values are:
	//
	// - `h1` (HTTP/1.1)
	// - `h2` (HTTP/2)
	// - `h2c` (cleartext HTTP/2)
	// - `h3` (HTTP/3)
	//
	// If enabling `h2` or `h2c`, `h1` must also be enabled;
	// this is due to current limitations in the Go standard
	// library.
	//
	// HTTP/2 operates only over TLS (HTTPS). HTTP/3 opens
	// a UDP socket to serve QUIC connections.
	//
	// H2C operates over plain TCP if the client supports it;
	// however, because this is not implemented by the Go
	// standard library, other server options are not compatible
	// and will not be applied to H2C requests. Do not enable this
	// only to achieve maximum client compatibility. In practice,
	// very few clients implement H2C, and even fewer require it.
	// Enabling H2C can be useful for serving/proxying gRPC
	// if encryption is not possible or desired.
	//
	// We recommend for most users to simply let Caddy use the
	// default settings.
	//
	// Default: `[h1 h2 h3]`
	Protocols []string `json:"protocols,omitempty"`

	// If set, metrics observations will be enabled.
	// This setting is EXPERIMENTAL and subject to change.
	Metrics *Metrics `json:"metrics,omitempty"`

	name string

	primaryHandlerChain Handler
	errorHandlerChain   Handler
	listenerWrappers    []caddy.ListenerWrapper
	listeners           []net.Listener

	tlsApp       *caddytls.TLS
	events       *caddyevents.App
	logger       *zap.Logger
	accessLogger *zap.Logger
	errorLogger  *zap.Logger
	ctx          caddy.Context

	server      *http.Server
	h3server    *http3.Server
	h3listeners []net.PacketConn // TODO: we have to hold these because quic-go won't close listeners it didn't create
	addresses   []caddy.NetworkAddress

	trustedProxies IPRangeSource

	shutdownAt   time.Time
	shutdownAtMu *sync.RWMutex

	// registered callback functions
	connStateFuncs   []func(net.Conn, http.ConnState)
	connContextFuncs []func(ctx context.Context, c net.Conn) context.Context
	onShutdownFuncs  []func()
}

// ServeHTTP is the entry point for all HTTP requests.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "Caddy")

	// advertise HTTP/3, if enabled
	if s.h3server != nil {
		// keep track of active requests for QUIC transport purposes
		atomic.AddInt64(&s.activeRequests, 1)
		defer atomic.AddInt64(&s.activeRequests, -1)

		if r.ProtoMajor < 3 {
			err := s.h3server.SetQuicHeaders(w.Header())
			if err != nil {
				s.logger.Error("setting HTTP/3 Alt-Svc header", zap.Error(err))
			}
		}
	}

	// reject very long methods; probably a mistake or an attack
	if len(r.Method) > 32 {
		if s.shouldLogRequest(r) {
			s.accessLogger.Debug("rejecting request with long method",
				zap.String("method_trunc", r.Method[:32]),
				zap.String("remote_addr", r.RemoteAddr))
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	repl := caddy.NewReplacer()
	r = PrepareRequest(r, repl, w, s)

	// encode the request for logging purposes before
	// it enters any handler chain; this is necessary
	// to capture the original request in case it gets
	// modified during handling
	shouldLogCredentials := s.Logs != nil && s.Logs.ShouldLogCredentials
	loggableReq := zap.Object("request", LoggableHTTPRequest{
		Request:              r,
		ShouldLogCredentials: shouldLogCredentials,
	})
	errLog := s.errorLogger.With(loggableReq)

	var duration time.Duration

	if s.shouldLogRequest(r) {
		wrec := NewResponseRecorder(w, nil, nil)
		w = wrec

		// capture the original version of the request
		accLog := s.accessLogger.With(loggableReq)

		defer func() {
			// this request may be flagged as omitted from the logs
			if skipLog, ok := GetVar(r.Context(), SkipLogVar).(bool); ok && skipLog {
				return
			}

			repl.Set("http.response.status", wrec.Status()) // will be 0 if no response is written by us (Go will write 200 to client)
			repl.Set("http.response.size", wrec.Size())
			repl.Set("http.response.duration", duration)
			repl.Set("http.response.duration_ms", duration.Seconds()*1e3) // multiply seconds to preserve decimal (see #4666)

			logger := accLog
			if s.Logs != nil {
				logger = s.Logs.wrapLogger(logger, r.Host)
			}

			log := logger.Info
			if wrec.Status() >= 400 {
				log = logger.Error
			}

			userID, _ := repl.GetString("http.auth.user.id")

			log("handled request",
				zap.String("user_id", userID),
				zap.Duration("duration", duration),
				zap.Int("size", wrec.Size()),
				zap.Int("status", wrec.Status()),
				zap.Object("resp_headers", LoggableHTTPHeader{
					Header:               wrec.Header(),
					ShouldLogCredentials: shouldLogCredentials,
				}),
			)
		}()
	}

	start := time.Now()

	// guarantee ACME HTTP challenges; handle them
	// separately from any user-defined handlers
	if s.tlsApp.HandleHTTPChallenge(w, r) {
		duration = time.Since(start)
		return
	}

	// execute the primary handler chain
	err := s.primaryHandlerChain.ServeHTTP(w, r)
	duration = time.Since(start)

	// if no errors, we're done!
	if err == nil {
		return
	}

	// restore original request before invoking error handler chain (issue #3717)
	// TODO: this does not restore original headers, if modified (for efficiency)
	origReq := r.Context().Value(OriginalRequestCtxKey).(http.Request)
	r.Method = origReq.Method
	r.RemoteAddr = origReq.RemoteAddr
	r.RequestURI = origReq.RequestURI
	cloneURL(origReq.URL, r.URL)

	// prepare the error log
	logger := errLog
	if s.Logs != nil {
		logger = s.Logs.wrapLogger(logger, r.Host)
	}
	logger = logger.With(zap.Duration("duration", duration))

	// get the values that will be used to log the error
	errStatus, errMsg, errFields := errLogValues(err)

	// add HTTP error information to request context
	r = s.Errors.WithError(r, err)

	if s.Errors != nil && len(s.Errors.Routes) > 0 {
		// execute user-defined error handling route
		err2 := s.errorHandlerChain.ServeHTTP(w, r)
		if err2 == nil {
			// user's error route handled the error response
			// successfully, so now just log the error
			logger.Debug(errMsg, errFields...)
		} else {
			// well... this is awkward
			errFields = append([]zapcore.Field{
				zap.String("error", err2.Error()),
				zap.Namespace("first_error"),
				zap.String("msg", errMsg),
			}, errFields...)
			logger.Error("error handling handler error", errFields...)
			if handlerErr, ok := err.(HandlerError); ok {
				w.WriteHeader(handlerErr.StatusCode)
			} else {
				w.WriteHeader(http.StatusInternalServerError)
			}
		}
	} else {
		if errStatus >= 500 {
			logger.Error(errMsg, errFields...)
		} else {
			logger.Debug(errMsg, errFields...)
		}
		w.WriteHeader(errStatus)
	}
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
			return Error(http.StatusMisdirectedRequest, err)
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

		// Apparently, Linux requires all bound ports to be distinct
		// *regardless of host interface* even if the addresses are
		// in fact different; binding "192.168.0.1:9000" and then
		// ":9000" will fail for ":9000" because "address is already
		// in use" even though it's not, and the same bindings work
		// fine on macOS. I also found on Linux that listening on
		// "[::]:9000" would fail with a similar error, except with
		// the address "0.0.0.0:9000", as if deliberately ignoring
		// that I specified the IPv6 interface explicitly. This seems
		// to be a major bug in the Linux network stack and I don't
		// know why it hasn't been fixed yet, so for now we have to
		// special-case ourselves around Linux like a doting parent.
		// The second issue seems very similar to a discussion here:
		// https://github.com/nodejs/node/issues/9390
		//
		// This is very easy to reproduce by creating an HTTP server
		// that listens to both addresses or just one with a host
		// interface; or for a more confusing reproduction, try
		// listening on "127.0.0.1:80" and ":443" and you'll see
		// the error, if you take away the GOOS condition below.
		//
		// So, an address is equivalent if the port is in the port
		// range, and if not on Linux, the host is the same... sigh.
		if (runtime.GOOS == "linux" || thisAddrs.Host == laddrs.Host) &&
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

// findLastRouteWithHostMatcher returns the index of the last route
// in the server which has a host matcher. Used during Automatic HTTPS
// to determine where to insert the HTTP->HTTPS redirect route, such
// that it is after any other host matcher but before any "catch-all"
// route without a host matcher.
func (s *Server) findLastRouteWithHostMatcher() int {
	foundHostMatcher := false
	lastIndex := len(s.Routes)

	for i, route := range s.Routes {
		// since we want to break out of an inner loop, use a closure
		// to allow us to use 'return' when we found a host matcher
		found := (func() bool {
			for _, sets := range route.MatcherSets {
				for _, matcher := range sets {
					switch matcher.(type) {
					case *MatchHost:
						foundHostMatcher = true
						return true
					}
				}
			}
			return false
		})()

		// if we found the host matcher, change the lastIndex to
		// just after the current route
		if found {
			lastIndex = i + 1
		}
	}

	// If we didn't actually find a host matcher, return 0
	// because that means every defined route was a "catch-all".
	// See https://caddy.community/t/how-to-set-priority-in-caddyfile/13002/8
	if !foundHostMatcher {
		return 0
	}

	return lastIndex
}

// serveHTTP3 creates a QUIC listener, configures an HTTP/3 server if
// not already done, and then uses that server to serve HTTP/3 over
// the listener, with Server s as the handler.
func (s *Server) serveHTTP3(addr caddy.NetworkAddress, tlsCfg *tls.Config) error {
	switch addr.Network {
	case "unix":
		addr.Network = "unixgram"
	case "tcp4":
		addr.Network = "udp4"
	case "tcp6":
		addr.Network = "udp6"
	default:
		addr.Network = "udp" // TODO: Maybe a better default is to not enable HTTP/3 if we do not know the network?
	}

	lnAny, err := addr.Listen(s.ctx, 0, net.ListenConfig{})
	if err != nil {
		return err
	}
	ln := lnAny.(net.PacketConn)

	h3ln, err := caddy.ListenQUIC(ln, tlsCfg, &s.activeRequests)
	if err != nil {
		return fmt.Errorf("starting HTTP/3 QUIC listener: %v", err)
	}

	// create HTTP/3 server if not done already
	if s.h3server == nil {
		s.h3server = &http3.Server{
			Handler:        s,
			TLSConfig:      tlsCfg,
			MaxHeaderBytes: s.MaxHeaderBytes,
			// TODO: remove this config when draft versions are no longer supported (we have no need to support drafts)
			QuicConfig: &quic.Config{
				Versions: []quic.VersionNumber{quic.Version1, quic.Version2},
			},
		}
	}

	s.h3listeners = append(s.h3listeners, lnAny.(net.PacketConn))

	//nolint:errcheck
	go s.h3server.ServeListener(h3ln)

	return nil
}

// configureServer applies/binds the registered callback functions to the server.
func (s *Server) configureServer(server *http.Server) {
	for _, f := range s.connStateFuncs {
		if server.ConnState != nil {
			baseConnStateFunc := server.ConnState
			server.ConnState = func(conn net.Conn, state http.ConnState) {
				baseConnStateFunc(conn, state)
				f(conn, state)
			}
		} else {
			server.ConnState = f
		}
	}

	for _, f := range s.connContextFuncs {
		if server.ConnContext != nil {
			baseConnContextFunc := server.ConnContext
			server.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
				return f(baseConnContextFunc(ctx, c), c)
			}
		} else {
			server.ConnContext = f
		}
	}

	for _, f := range s.onShutdownFuncs {
		server.RegisterOnShutdown(f)
	}
}

// RegisterConnState registers f to be invoked on s.ConnState.
func (s *Server) RegisterConnState(f func(net.Conn, http.ConnState)) {
	s.connStateFuncs = append(s.connStateFuncs, f)
}

// RegisterConnContext registers f to be invoked as part of s.ConnContext.
func (s *Server) RegisterConnContext(f func(ctx context.Context, c net.Conn) context.Context) {
	s.connContextFuncs = append(s.connContextFuncs, f)
}

// RegisterOnShutdown registers f to be invoked on server shutdown.
func (s *Server) RegisterOnShutdown(f func()) {
	s.onShutdownFuncs = append(s.onShutdownFuncs, f)
}

// HTTPErrorConfig determines how to handle errors
// from the HTTP handlers.
type HTTPErrorConfig struct {
	// The routes to evaluate after the primary handler
	// chain returns an error. In an error route, extra
	// placeholders are available:
	//
	// Placeholder | Description
	// ------------|---------------
	// `{http.error.status_code}` | The recommended HTTP status code
	// `{http.error.status_text}` | The status text associated with the recommended status code
	// `{http.error.message}`     | The error message
	// `{http.error.trace}`       | The origin of the error
	// `{http.error.id}`          | An identifier for this occurrence of the error
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
	repl.Set("http.error", err)
	if handlerErr, ok := err.(HandlerError); ok {
		repl.Set("http.error.status_code", handlerErr.StatusCode)
		repl.Set("http.error.status_text", http.StatusText(handlerErr.StatusCode))
		repl.Set("http.error.id", handlerErr.ID)
		repl.Set("http.error.trace", handlerErr.Trace)
		if handlerErr.Err != nil {
			repl.Set("http.error.message", handlerErr.Err.Error())
		} else {
			repl.Set("http.error.message", http.StatusText(handlerErr.StatusCode))
		}
	}

	return r
}

// shouldLogRequest returns true if this request should be logged.
func (s *Server) shouldLogRequest(r *http.Request) bool {
	if s.accessLogger == nil || s.Logs == nil {
		// logging is disabled
		return false
	}
	if _, ok := s.Logs.LoggerNames[r.Host]; ok {
		// this host is mapped to a particular logger name
		return true
	}
	for _, dh := range s.Logs.SkipHosts {
		// logging for this particular host is disabled
		if certmagic.MatchWildcard(r.Host, dh) {
			return false
		}
	}
	// if configured, this host is not mapped and thus must not be logged
	return !s.Logs.SkipUnmappedHosts
}

// protocol returns true if the protocol proto is configured/enabled.
func (s *Server) protocol(proto string) bool {
	for _, p := range s.Protocols {
		if p == proto {
			return true
		}
	}
	return false
}

// Listeners returns the server's listeners. These are active listeners,
// so calling Accept() or Close() on them will probably break things.
// They are made available here for read-only purposes (e.g. Addr())
// and for type-asserting for purposes where you know what you're doing.
//
// EXPERIMENTAL: Subject to change or removal.
func (s *Server) Listeners() []net.Listener { return s.listeners }

// PrepareRequest fills the request r for use in a Caddy HTTP handler chain. w and s can
// be nil, but the handlers will lose response placeholders and access to the server.
func PrepareRequest(r *http.Request, repl *caddy.Replacer, w http.ResponseWriter, s *Server) *http.Request {
	// set up the context for the request
	ctx := context.WithValue(r.Context(), caddy.ReplacerCtxKey, repl)
	ctx = context.WithValue(ctx, ServerCtxKey, s)
	ctx = context.WithValue(ctx, VarsCtxKey, map[string]any{
		TrustedProxyVarKey: determineTrustedProxy(r, s),
	})
	ctx = context.WithValue(ctx, routeGroupCtxKey, make(map[string]struct{}))
	var url2 url.URL // avoid letting this escape to the heap
	ctx = context.WithValue(ctx, OriginalRequestCtxKey, originalRequest(r, &url2))
	r = r.WithContext(ctx)

	// once the pointer to the request won't change
	// anymore, finish setting up the replacer
	addHTTPVarsToReplacer(repl, r, w)

	return r
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

// determineTrustedProxy parses the remote IP address of
// the request, and determines (if the server configured it)
// if the client is a trusted proxy.
func determineTrustedProxy(r *http.Request, s *Server) bool {
	// If there's no server, then we can't check anything
	if s == nil {
		return false
	}

	// Parse the remote IP, ignore the error as non-fatal,
	// but the remote IP is required to continue, so we
	// just return early. This should probably never happen
	// though, unless some other module manipulated the request's
	// remote address and used an invalid value.
	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}

	// Client IP may contain a zone if IPv6, so we need
	// to pull that out before parsing the IP
	clientIP, _, _ = strings.Cut(clientIP, "%")
	ipAddr, err := netip.ParseAddr(clientIP)
	if err != nil {
		return false
	}

	// Check if the client is a trusted proxy
	if s.trustedProxies == nil {
		return false
	}
	for _, ipRange := range s.trustedProxies.GetIPRanges(r) {
		if ipRange.Contains(ipAddr) {
			return true
		}
	}

	return false
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

// Context keys for HTTP request context values.
const (
	// For referencing the server instance
	ServerCtxKey caddy.CtxKey = "server"

	// For the request's variable table
	VarsCtxKey caddy.CtxKey = "vars"

	// For a partial copy of the unmodified request that
	// originally came into the server's entry handler
	OriginalRequestCtxKey caddy.CtxKey = "original_request"

	// For tracking whether the client is a trusted proxy
	TrustedProxyVarKey string = "trusted_proxy"
)
