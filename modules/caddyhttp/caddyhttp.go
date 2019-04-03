package caddyhttp

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"bitbucket.org/lightcodelabs/caddy2"
)

func init() {
	err := caddy2.RegisterModule(caddy2.Module{
		Name: "http",
		New:  func() (interface{}, error) { return new(httpModuleConfig), nil },
	})
	if err != nil {
		log.Fatal(err)
	}
}

type httpModuleConfig struct {
	Servers map[string]httpServerConfig `json:"servers"`

	servers []*http.Server
}

func (hc *httpModuleConfig) Run() error {
	// TODO: Either prevent overlapping listeners on different servers, or combine them into one
	// TODO: A way to loop requests back through, so have them start the matching over again, but keeping any mutations
	for _, srv := range hc.Servers {
		// set up the routes
		for i, route := range srv.Routes {
			// matchers
			for modName, rawMsg := range route.Matchers {
				val, err := caddy2.LoadModule("http.matchers."+modName, rawMsg)
				if err != nil {
					return fmt.Errorf("loading matcher module '%s': %v", modName, err)
				}
				srv.Routes[i].matchers = append(srv.Routes[i].matchers, val.(RouteMatcher))
			}

			// middleware
			for j, rawMsg := range route.Apply {
				mid, err := caddy2.LoadModuleInlineName("http.middleware", rawMsg)
				if err != nil {
					return fmt.Errorf("loading middleware module in position %d: %v", j, err)
				}
				srv.Routes[i].middleware = append(srv.Routes[i].middleware, mid.(MiddlewareHandler))
			}

			// responder
			if route.Respond != nil {
				resp, err := caddy2.LoadModuleInlineName("http.responders", route.Respond)
				if err != nil {
					return fmt.Errorf("loading responder module: %v", err)
				}
				srv.Routes[i].responder = resp.(Handler)
			}
		}

		s := &http.Server{
			ReadTimeout:       time.Duration(srv.ReadTimeout),
			ReadHeaderTimeout: time.Duration(srv.ReadHeaderTimeout),
			Handler:           srv,
		}

		for _, lnAddr := range srv.Listen {
			network, addrs, err := parseListenAddr(lnAddr)
			if err != nil {
				return fmt.Errorf("parsing listen address '%s': %v", lnAddr, err)
			}
			for _, addr := range addrs {
				ln, err := caddy2.Listen(network, addr)
				if err != nil {
					return fmt.Errorf("%s: listening on %s: %v", network, addr, err)
				}
				go s.Serve(ln)
				hc.servers = append(hc.servers, s)
			}
		}
	}

	return nil
}

func (hc *httpModuleConfig) Cancel() error {
	for _, s := range hc.servers {
		err := s.Shutdown(context.Background()) // TODO
		if err != nil {
			return err
		}
	}
	return nil
}

type httpServerConfig struct {
	Listen            []string        `json:"listen"`
	ReadTimeout       caddy2.Duration `json:"read_timeout"`
	ReadHeaderTimeout caddy2.Duration `json:"read_header_timeout"`
	HiddenFiles       []string        `json:"hidden_files"` // TODO:... experimenting with shared/common state
	Routes            []serverRoute   `json:"routes"`
}

func (s httpServerConfig) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var mid []Middleware // TODO: see about using make() for performance reasons
	var responder Handler
	mrw := &middlewareResponseWriter{ResponseWriterWrapper: &ResponseWriterWrapper{w}}

	for _, route := range s.Routes {
		matched := len(route.matchers) == 0
		for _, m := range route.matchers {
			if m.Match(r) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		for _, m := range route.middleware {
			mid = append(mid, func(next HandlerFunc) HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) error {
					return m.ServeHTTP(mrw, r, next)
				}
			})
		}
		if responder == nil {
			responder = route.responder
		}
	}

	// build the middleware stack, with the responder at the end
	stack := HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		if responder == nil {
			return nil
		}
		mrw.allowWrites = true
		return responder.ServeHTTP(w, r)
	})
	for i := len(mid) - 1; i >= 0; i-- {
		stack = mid[i](stack)
	}

	err := stack.ServeHTTP(w, r)
	if err != nil {
		// TODO: error handling
		log.Printf("[ERROR] TODO: error handling: %v", err)
	}
}

type serverRoute struct {
	Matchers map[string]json.RawMessage `json:"match"`
	Apply    []json.RawMessage          `json:"apply"`
	Respond  json.RawMessage            `json:"respond"`

	// decoded values
	matchers   []RouteMatcher
	middleware []MiddlewareHandler
	responder  Handler
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
