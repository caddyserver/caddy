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
	Group    string                     `json:"group"`
	Matchers map[string]json.RawMessage `json:"match"`
	Apply    []json.RawMessage          `json:"apply"`
	Respond  json.RawMessage            `json:"respond"`

	Terminal bool `json:"terminal"`

	// decoded values
	matchers   []RequestMatcher
	middleware []MiddlewareHandler
	responder  Handler
}

// RouteList is a list of server routes that can
// create a middleware chain.
type RouteList []ServerRoute

// Provision sets up all the routes by loading the modules.
func (routes RouteList) Provision(ctx caddy2.Context) error {
	for i, route := range routes {
		// matchers
		for modName, rawMsg := range route.Matchers {
			val, err := ctx.LoadModule("http.matchers."+modName, rawMsg)
			if err != nil {
				return fmt.Errorf("loading matcher module '%s': %v", modName, err)
			}
			routes[i].matchers = append(routes[i].matchers, val.(RequestMatcher))
		}
		routes[i].Matchers = nil // allow GC to deallocate - TODO: Does this help?

		// middleware
		for j, rawMsg := range route.Apply {
			mid, err := ctx.LoadModuleInline("middleware", "http.middleware", rawMsg)
			if err != nil {
				return fmt.Errorf("loading middleware module in position %d: %v", j, err)
			}
			routes[i].middleware = append(routes[i].middleware, mid.(MiddlewareHandler))
		}
		routes[i].Apply = nil // allow GC to deallocate - TODO: Does this help?

		// responder
		if route.Respond != nil {
			resp, err := ctx.LoadModuleInline("responder", "http.responders", route.Respond)
			if err != nil {
				return fmt.Errorf("loading responder module: %v", err)
			}
			routes[i].responder = resp.(Handler)
		}
		routes[i].Respond = nil // allow GC to deallocate - TODO: Does this help?
	}
	return nil
}

// BuildCompositeRoute creates a chain of handlers by applying all the matching
// routes. The returned ResponseWriter should be used instead of rw.
func (routes RouteList) BuildCompositeRoute(rw http.ResponseWriter, req *http.Request) (Handler, http.ResponseWriter) {
	mrw := &middlewareResponseWriter{ResponseWriterWrapper: &ResponseWriterWrapper{rw}}

	if len(routes) == 0 {
		return emptyHandler, mrw
	}

	var mid []Middleware
	var responder Handler
	groups := make(map[string]struct{})

routeLoop:
	for _, route := range routes {
		// see if route matches
		for _, m := range route.matchers {
			if !m.Match(req) {
				continue routeLoop
			}
		}

		// if route is part of a group, ensure only
		// the first matching route in the group is
		// applied
		if route.Group != "" {
			_, ok := groups[route.Group]
			if ok {
				// this group has already been satisfied
				// by a matching route
				continue
			}
			// this matching route satisfies the group
			groups[route.Group] = struct{}{}
		}

		// apply the rest of the route
		for _, m := range route.middleware {
			// we have to be sure to wrap m outside
			// of our current scope so that the
			// reference to this m isn't overwritten
			// on the next iteration, leaving only
			// the last middleware in the chain as
			// the ONLY middleware in the chain!
			mid = append(mid, wrapMiddleware(m))
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

	return stack, mrw
}

// wrapMiddleware wraps m such that it can be correctly
// appended to a list of middleware. This is necessary
// so that only the last middleware in a loop does not
// become the only middleware of the stack, repeatedly
// executed (i.e. it is necessary to keep a reference
// to this m outside of the scope of a loop)!
func wrapMiddleware(m MiddlewareHandler) Middleware {
	return func(next HandlerFunc) HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) error {
			// TODO: This is where request tracing could be implemented; also
			// see below to trace the responder as well
			// TODO: Trace a diff of the request, would be cool too! see what changed since the last middleware (host, headers, URI...)
			// TODO: see what the std lib gives us in terms of stack tracing too
			return m.ServeHTTP(w, r, next)
		}
	}
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

// Interface guard
var _ HTTPInterfaces = middlewareResponseWriter{}
