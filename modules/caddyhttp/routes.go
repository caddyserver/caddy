package caddyhttp

import (
	"encoding/json"
	"fmt"
	"net/http"

	"bitbucket.org/lightcodelabs/caddy2"
)

// ServerRoute represents a set of matching rules,
// middlewares, and a responder for handling HTTP
// requests.
type ServerRoute struct {
	Matchers map[string]json.RawMessage `json:"match"`
	Apply    []json.RawMessage          `json:"apply"`
	Respond  json.RawMessage            `json:"respond"`

	Terminal bool `json:"terminal"`

	// decoded values
	matchers   []RouteMatcher
	middleware []MiddlewareHandler
	responder  Handler
}

// RouteList is a list of server routes that can
// create a middleware chain.
type RouteList []ServerRoute

// Provision sets up all the routes by loading the modules.
func (routes RouteList) Provision() error {
	for i, route := range routes {
		// matchers
		for modName, rawMsg := range route.Matchers {
			val, err := caddy2.LoadModule("http.matchers."+modName, rawMsg)
			if err != nil {
				return fmt.Errorf("loading matcher module '%s': %v", modName, err)
			}
			routes[i].matchers = append(routes[i].matchers, val.(RouteMatcher))
		}
		routes[i].Matchers = nil // allow GC to deallocate - TODO: Does this help?

		// middleware
		for j, rawMsg := range route.Apply {
			mid, err := caddy2.LoadModuleInline("middleware", "http.middleware", rawMsg)
			if err != nil {
				return fmt.Errorf("loading middleware module in position %d: %v", j, err)
			}
			routes[i].middleware = append(routes[i].middleware, mid.(MiddlewareHandler))
		}
		routes[i].Apply = nil // allow GC to deallocate - TODO: Does this help?

		// responder
		if route.Respond != nil {
			resp, err := caddy2.LoadModuleInline("responder", "http.responders", route.Respond)
			if err != nil {
				return fmt.Errorf("loading responder module: %v", err)
			}
			routes[i].responder = resp.(Handler)
		}
		routes[i].Respond = nil // allow GC to deallocate - TODO: Does this help?
	}
	return nil
}

// BuildHandlerChain creates a chain of handlers by
// applying all the matching routes.
func (routes RouteList) BuildHandlerChain(w http.ResponseWriter, r *http.Request) Handler {
	if len(routes) == 0 {
		return emptyHandler
	}

	var mid []Middleware
	var responder Handler
	mrw := &middlewareResponseWriter{ResponseWriterWrapper: &ResponseWriterWrapper{w}}

routeLoop:
	for _, route := range routes {
		for _, m := range route.matchers {
			if !m.Match(r) {
				continue routeLoop
			}
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
		if route.Terminal {
			break
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

	return stack
}
