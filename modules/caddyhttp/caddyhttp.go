package caddyhttp

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	mathrand "math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"bitbucket.org/lightcodelabs/caddy2"
	"bitbucket.org/lightcodelabs/caddy2/modules/caddytls"
	"github.com/mholt/certmagic"
)

func init() {
	mathrand.Seed(time.Now().UnixNano())

	err := caddy2.RegisterModule(caddy2.Module{
		Name: "http",
		New:  func() (interface{}, error) { return new(httpModuleConfig), nil },
	})
	if err != nil {
		log.Fatal(err)
	}
}

type httpModuleConfig struct {
	Servers map[string]*httpServerConfig `json:"servers"`

	servers []*http.Server
}

func (hc *httpModuleConfig) Provision() error {
	// TODO: Either prevent overlapping listeners on different servers, or combine them into one
	for _, srv := range hc.Servers {
		err := srv.Routes.setup()
		if err != nil {
			return fmt.Errorf("setting up server routes: %v", err)
		}
		err = srv.Errors.Routes.setup()
		if err != nil {
			return fmt.Errorf("setting up server error handling routes: %v", err)
		}
	}

	return nil
}

func (hc *httpModuleConfig) Start(handle caddy2.Handle) error {
	err := hc.automaticHTTPS(handle)
	if err != nil {
		return fmt.Errorf("enabling automatic HTTPS: %v", err)
	}

	for srvName, srv := range hc.Servers {
		s := &http.Server{
			ReadTimeout:       time.Duration(srv.ReadTimeout),
			ReadHeaderTimeout: time.Duration(srv.ReadHeaderTimeout),
			Handler:           srv,
		}

		for _, lnAddr := range srv.Listen {
			network, addrs, err := parseListenAddr(lnAddr)
			if err != nil {
				return fmt.Errorf("%s: parsing listen address '%s': %v", srvName, lnAddr, err)
			}
			for _, addr := range addrs {
				ln, err := caddy2.Listen(network, addr)
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
				if len(srv.TLSConnPolicies) > 0 {
					tlsCfg, err := srv.TLSConnPolicies.TLSConfig(handle)
					if err != nil {
						return fmt.Errorf("%s/%s: making TLS configuration: %v", network, addr, err)
					}
					ln = tls.NewListener(ln, tlsCfg)
				}

				go s.Serve(ln)
				hc.servers = append(hc.servers, s)
			}
		}
	}

	return nil
}

func (hc *httpModuleConfig) Stop() error {
	for _, s := range hc.servers {
		err := s.Shutdown(context.Background()) // TODO
		if err != nil {
			return err
		}
	}
	return nil
}

func (hc *httpModuleConfig) automaticHTTPS(handle caddy2.Handle) error {
	tlsAppIface, err := handle.App("tls")
	if err != nil {
		return fmt.Errorf("getting tls app: %v", err)
	}
	tlsApp := tlsAppIface.(*caddytls.TLS)

	for srvName, srv := range hc.Servers {
		srv.tlsApp = tlsApp

		if srv.DisableAutoHTTPS {
			continue
		}

		// find all qualifying domain names, de-duplicated
		domainSet := make(map[string]struct{})
		for _, route := range srv.Routes {
			for _, m := range route.matchers {
				if hm, ok := m.(*matchHost); ok {
					for _, d := range *hm {
						if !certmagic.HostQualifies(d) {
							continue
						}
						domainSet[d] = struct{}{}
					}
				}
			}
		}

		if len(domainSet) > 0 {
			// marshal the domains into a slice
			var domains []string
			for d := range domainSet {
				domains = append(domains, d)
			}

			// manage their certificates
			err := tlsApp.Manage(domains)
			if err != nil {
				return fmt.Errorf("%s: managing certificate for %s: %s", srvName, domains, err)
			}

			// tell the server to use TLS
			srv.TLSConnPolicies = caddytls.ConnectionPolicies{
				{ALPN: defaultALPN},
			}

			// TODO: create HTTP->HTTPS redirects
		}
	}

	return nil
}

var defaultALPN = []string{"h2", "http/1.1"}

type httpServerConfig struct {
	Listen            []string                    `json:"listen"`
	ReadTimeout       caddy2.Duration             `json:"read_timeout"`
	ReadHeaderTimeout caddy2.Duration             `json:"read_header_timeout"`
	HiddenFiles       []string                    `json:"hidden_files"` // TODO:... experimenting with shared/common state
	Routes            routeList                   `json:"routes"`
	Errors            httpErrorConfig             `json:"errors"`
	TLSConnPolicies   caddytls.ConnectionPolicies `json:"tls_connection_policies"`
	DisableAutoHTTPS  bool                        `json:"disable_auto_https"`

	tlsApp *caddytls.TLS
}

type httpErrorConfig struct {
	Routes routeList `json:"routes"`
	// TODO: some way to configure the logging of errors, probably? standardize the logging configuration first.
}

// ServeHTTP is the entry point for all HTTP requests.
func (s httpServerConfig) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.tlsApp.HandleHTTPChallenge(w, r) {
		return
	}

	stack := s.Routes.buildMiddlewareChain(w, r)
	err := executeMiddlewareChain(w, r, stack)
	if err != nil {
		// add the error value to the request context so
		// it can be accessed by error handlers
		c := context.WithValue(r.Context(), ErrorCtxKey, err)
		r = r.WithContext(c)

		if len(s.Errors.Routes) == 0 {
			// TODO: implement a default error handler?
			log.Printf("[ERROR] %s", err)
		} else {
			errStack := s.Errors.Routes.buildMiddlewareChain(w, r)
			err := executeMiddlewareChain(w, r, errStack)
			if err != nil {
				// TODO: what should we do if the error handler has an error?
				log.Printf("[ERROR] handling error: %v", err)
			}
		}
	}
}

// executeMiddlewareChain executes stack with w and r. This function handles
// the special ErrRehandle error value, which reprocesses requests through
// the stack again. Any error value returned from this function would be an
// actual error that needs to be handled.
func executeMiddlewareChain(w http.ResponseWriter, r *http.Request, stack Handler) error {
	const maxRehandles = 3
	var err error
	for i := 0; i < maxRehandles; i++ {
		err = stack.ServeHTTP(w, r)
		if err != ErrRehandle {
			break
		}
		if i == maxRehandles-1 {
			return fmt.Errorf("too many rehandles")
		}
	}
	return err
}

// RouteMatcher is a type that can match to a request.
// A route matcher MUST NOT modify the request.
type RouteMatcher interface {
	Match(*http.Request) bool
}

// Middleware chains one Handler to the next by being passed
// the next Handler in the chain.
type Middleware func(HandlerFunc) HandlerFunc

// MiddlewareHandler is a Handler that includes a reference
// to the next middleware handler in the chain. Middleware
// handlers MUST NOT call Write() or WriteHeader() on the
// response writer; doing so will panic. See Handler godoc
// for more information.
type MiddlewareHandler interface {
	ServeHTTP(http.ResponseWriter, *http.Request, Handler) error
}

// Handler is like http.Handler except ServeHTTP may return an error.
//
// Middleware and responder handlers both implement this method.
// Middleware must not call Write or WriteHeader on the ResponseWriter;
// doing so will cause a panic. Responders should write to the response
// if there was not an error.
//
// If any handler encounters an error, it should be returned for proper
// handling. Return values should be propagated down the middleware chain
// by returning it unchanged.
type Handler interface {
	ServeHTTP(http.ResponseWriter, *http.Request) error
}

// HandlerFunc is a convenience type like http.HandlerFunc.
type HandlerFunc func(http.ResponseWriter, *http.Request) error

// ServeHTTP implements the Handler interface.
func (f HandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	return f(w, r)
}

// emptyHandler is used as a no-op handler, which is
// sometimes better than a nil Handler pointer.
var emptyHandler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error { return nil }

func parseListenAddr(a string) (network string, addrs []string, err error) {
	network = "tcp"
	if idx := strings.Index(a, "/"); idx >= 0 {
		network = strings.ToLower(strings.TrimSpace(a[:idx]))
		a = a[idx+1:]
	}
	var host, port string
	host, port, err = net.SplitHostPort(a)
	if err != nil {
		return
	}
	ports := strings.SplitN(port, "-", 2)
	if len(ports) == 1 {
		ports = append(ports, ports[0])
	}
	var start, end int
	start, err = strconv.Atoi(ports[0])
	if err != nil {
		return
	}
	end, err = strconv.Atoi(ports[1])
	if err != nil {
		return
	}
	if end < start {
		err = fmt.Errorf("end port must be greater than start port")
		return
	}
	for p := start; p <= end; p++ {
		addrs = append(addrs, net.JoinHostPort(host, fmt.Sprintf("%d", p)))
	}
	return
}

type middlewareResponseWriter struct {
	*ResponseWriterWrapper
	allowWrites bool
}

func (mrw middlewareResponseWriter) WriteHeader(statusCode int) {
	if !mrw.allowWrites {
		panic("WriteHeader: middleware cannot write to the response")
	}
	mrw.ResponseWriterWrapper.WriteHeader(statusCode)
}

func (mrw middlewareResponseWriter) Write(b []byte) (int, error) {
	if !mrw.allowWrites {
		panic("Write: middleware cannot write to the response")
	}
	return mrw.ResponseWriterWrapper.Write(b)
}

// Interface guards
var _ HTTPInterfaces = middlewareResponseWriter{}
