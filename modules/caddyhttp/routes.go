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
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
)

// Route consists of a set of rules for matching HTTP requests,
// a list of handlers to execute, and optional flow control
// parameters which customize the handling of HTTP requests
// in a highly flexible and performant manner.
type Route struct {
	// Group is an optional name for a group to which this
	// route belongs. Grouping a route makes it mutually
	// exclusive with others in its group; if a route belongs
	// to a group, only the first matching route in that group
	// will be executed.
	Group string `json:"group,omitempty"`

	// The matcher sets which will be used to qualify this
	// route for a request (essentially the "if" statement
	// of this route). Each matcher set is OR'ed, but matchers
	// within a set are AND'ed together.
	MatcherSetsRaw RawMatcherSets `json:"match,omitempty" caddy:"namespace=http.matchers"`

	// The list of handlers for this route. Upon matching a request, they are chained
	// together in a middleware fashion: requests flow from the first handler to the last
	// (top of the list to the bottom), with the possibility that any handler could stop
	// the chain and/or return an error. Responses flow back through the chain (bottom of
	// the list to the top) as they are written out to the client.
	//
	// Not all handlers call the next handler in the chain. For example, the reverse_proxy
	// handler always sends a request upstream or returns an error. Thus, configuring
	// handlers after reverse_proxy in the same route is illogical, since they would never
	// be executed. You will want to put handlers which originate the response at the very
	// end of your route(s). The documentation for a module should state whether it invokes
	// the next handler, but sometimes it is common sense.
	//
	// Some handlers manipulate the response. Remember that requests flow down the list, and
	// responses flow up the list.
	//
	// For example, if you wanted to use both `templates` and `encode` handlers, you would
	// need to put `templates` after `encode` in your route, because responses flow up.
	// Thus, `templates` will be able to parse and execute the plain-text response as a
	// template, and then return it up to the `encode` handler which will then compress it
	// into a binary format.
	//
	// If `templates` came before `encode`, then `encode` would write a compressed,
	// binary-encoded response to `templates` which would not be able to parse the response
	// properly.
	//
	// The correct order, then, is this:
	//
	//     [
	//         {"handler": "encode"},
	//         {"handler": "templates"},
	//         {"handler": "file_server"}
	//     ]
	//
	// The request flows ⬇️ DOWN (`encode` -> `templates` -> `file_server`).
	//
	// 1. First, `encode` will choose how to `encode` the response and wrap the response.
	// 2. Then, `templates` will wrap the response with a buffer.
	// 3. Finally, `file_server` will originate the content from a file.
	//
	// The response flows ⬆️ UP (`file_server` -> `templates` -> `encode`):
	//
	// 1. First, `file_server` will write the file to the response.
	// 2. That write will be buffered and then executed by `templates`.
	// 3. Lastly, the write from `templates` will flow into `encode` which will compress the stream.
	//
	// If you think of routes in this way, it will be easy and even fun to solve the puzzle of writing correct routes.
	HandlersRaw []json.RawMessage `json:"handle,omitempty" caddy:"namespace=http.handlers inline_key=handler"`

	// If true, no more routes will be executed after this one.
	Terminal bool `json:"terminal,omitempty"`

	// decoded values
	MatcherSets MatcherSets         `json:"-"`
	Handlers    []MiddlewareHandler `json:"-"`

	middleware []Middleware
}

// Empty returns true if the route has all zero/default values.
func (r Route) Empty() bool {
	return len(r.MatcherSetsRaw) == 0 &&
		len(r.MatcherSets) == 0 &&
		len(r.HandlersRaw) == 0 &&
		len(r.Handlers) == 0 &&
		!r.Terminal &&
		r.Group == ""
}

func (r Route) String() string {
	handlersRaw := "["
	for _, hr := range r.HandlersRaw {
		handlersRaw += " " + string(hr)
	}
	handlersRaw += "]"

	return fmt.Sprintf(`{Group:"%s" MatcherSetsRaw:%s HandlersRaw:%s Terminal:%t}`,
		r.Group, r.MatcherSetsRaw, handlersRaw, r.Terminal)
}

// Provision sets up both the matchers and handlers in the route.
func (r *Route) Provision(ctx caddy.Context, metrics *Metrics) error {
	err := r.ProvisionMatchers(ctx)
	if err != nil {
		return err
	}
	return r.ProvisionHandlers(ctx, metrics)
}

// ProvisionMatchers sets up all the matchers by loading the
// matcher modules. Only call this method directly if you need
// to set up matchers and handlers separately without having
// to provision a second time; otherwise use Provision instead.
func (r *Route) ProvisionMatchers(ctx caddy.Context) error {
	// matchers
	matchersIface, err := ctx.LoadModule(r, "MatcherSetsRaw")
	if err != nil {
		return fmt.Errorf("loading matcher modules: %v", err)
	}
	err = r.MatcherSets.FromInterface(matchersIface)
	if err != nil {
		return err
	}
	return nil
}

// ProvisionHandlers sets up all the handlers by loading the
// handler modules. Only call this method directly if you need
// to set up matchers and handlers separately without having
// to provision a second time; otherwise use Provision instead.
func (r *Route) ProvisionHandlers(ctx caddy.Context, metrics *Metrics) error {
	handlersIface, err := ctx.LoadModule(r, "HandlersRaw")
	if err != nil {
		return fmt.Errorf("loading handler modules: %v", err)
	}
	for _, handler := range handlersIface.([]any) {
		r.Handlers = append(r.Handlers, handler.(MiddlewareHandler))
	}

	// Make ProvisionHandlers idempotent by clearing the middleware field
	r.middleware = []Middleware{}

	// pre-compile the middleware handler chain
	for _, midhandler := range r.Handlers {
		r.middleware = append(r.middleware, wrapMiddleware(ctx, midhandler, metrics))
	}
	return nil
}

// Compile prepares a middleware chain from the route list.
// This should only be done once during the request, just
// before the middleware chain is executed.
func (r Route) Compile(next Handler) Handler {
	return wrapRoute(r)(next)
}

// RouteList is a list of server routes that can
// create a middleware chain.
type RouteList []Route

// Provision sets up both the matchers and handlers in the routes.
func (routes RouteList) Provision(ctx caddy.Context) error {
	err := routes.ProvisionMatchers(ctx)
	if err != nil {
		return err
	}
	return routes.ProvisionHandlers(ctx, nil)
}

// ProvisionMatchers sets up all the matchers by loading the
// matcher modules. Only call this method directly if you need
// to set up matchers and handlers separately without having
// to provision a second time; otherwise use Provision instead.
func (routes RouteList) ProvisionMatchers(ctx caddy.Context) error {
	for i := range routes {
		err := routes[i].ProvisionMatchers(ctx)
		if err != nil {
			return fmt.Errorf("route %d: %v", i, err)
		}
	}
	return nil
}

// ProvisionHandlers sets up all the handlers by loading the
// handler modules. Only call this method directly if you need
// to set up matchers and handlers separately without having
// to provision a second time; otherwise use Provision instead.
func (routes RouteList) ProvisionHandlers(ctx caddy.Context, metrics *Metrics) error {
	for i := range routes {
		err := routes[i].ProvisionHandlers(ctx, metrics)
		if err != nil {
			return fmt.Errorf("route %d: %v", i, err)
		}
	}
	return nil
}

// Compile prepares a middleware chain from the route list.
// This should only be done either once during provisioning
// for top-level routes, or on each request just before the
// middleware chain is executed for subroutes.
func (routes RouteList) Compile(next Handler) Handler {
	mid := make([]Middleware, 0, len(routes))
	for _, route := range routes {
		mid = append(mid, wrapRoute(route))
	}
	stack := next
	for i := len(mid) - 1; i >= 0; i-- {
		stack = mid[i](stack)
	}
	return stack
}

// wrapRoute wraps route with a middleware and handler so that it can
// be chained in and defer evaluation of its matchers to request-time.
// Like wrapMiddleware, it is vital that this wrapping takes place in
// its own stack frame so as to not overwrite the reference to the
// intended route by looping and changing the reference each time.
func wrapRoute(route Route) Middleware {
	return func(next Handler) Handler {
		return HandlerFunc(func(rw http.ResponseWriter, req *http.Request) error {
			// TODO: Update this comment, it seems we've moved the copy into the handler?
			// copy the next handler (it's an interface, so it's just
			// a very lightweight copy of a pointer); this is important
			// because this is a closure to the func below, which
			// re-assigns the value as it compiles the middleware stack;
			// if we don't make this copy, we'd affect the underlying
			// pointer for all future request (yikes); we could
			// alternatively solve this by moving the func below out of
			// this closure and into a standalone package-level func,
			// but I just thought this made more sense
			nextCopy := next

			// route must match at least one of the matcher sets
			matches, err := route.MatcherSets.AnyMatchWithError(req)
			if err != nil {
				// allow matchers the opportunity to short circuit
				// the request and trigger the error handling chain
				return err
			}
			if !matches {
				// call the next handler, and skip this one,
				// since the matcher didn't match
				return nextCopy.ServeHTTP(rw, req)
			}

			// if route is part of a group, ensure only the
			// first matching route in the group is applied
			if route.Group != "" {
				groups := req.Context().Value(routeGroupCtxKey).(map[string]struct{})

				if _, ok := groups[route.Group]; ok {
					// this group has already been
					// satisfied by a matching route
					return nextCopy.ServeHTTP(rw, req)
				}

				// this matching route satisfies the group
				groups[route.Group] = struct{}{}
			}

			// make terminal routes terminate
			if route.Terminal {
				if _, ok := req.Context().Value(ErrorCtxKey).(error); ok {
					nextCopy = errorEmptyHandler
				} else {
					nextCopy = emptyHandler
				}
			}

			// compile this route's handler stack
			for i := len(route.middleware) - 1; i >= 0; i-- {
				nextCopy = route.middleware[i](nextCopy)
			}

			return nextCopy.ServeHTTP(rw, req)
		})
	}
}

// wrapMiddleware wraps mh such that it can be correctly
// appended to a list of middleware in preparation for
// compiling into a handler chain. We can't do this inline
// inside a loop, because it relies on a reference to mh
// not changing until the execution of its handler (which
// is deferred by multiple func closures). In other words,
// we need to pull this particular MiddlewareHandler
// pointer into its own stack frame to preserve it so it
// won't be overwritten in future loop iterations.
func wrapMiddleware(ctx caddy.Context, mh MiddlewareHandler, metrics *Metrics) Middleware {
	handlerToUse := mh
	if metrics != nil {
		// wrap the middleware with metrics instrumentation
		handlerToUse = newMetricsInstrumentedHandler(ctx, caddy.GetModuleName(mh), mh, metrics)
	}

	return func(next Handler) Handler {
		// copy the next handler (it's an interface, so it's
		// just a very lightweight copy of a pointer); this
		// is a safeguard against the handler changing the
		// value, which could affect future requests (yikes)
		nextCopy := next

		return HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			// EXPERIMENTAL: Trace each module that gets invoked
			if server, ok := r.Context().Value(ServerCtxKey).(*Server); ok && server != nil {
				server.logTrace(handlerToUse)
			}
			return handlerToUse.ServeHTTP(w, r, nextCopy)
		})
	}
}

// MatcherSet is a set of matchers which
// must all match in order for the request
// to be matched successfully.
type MatcherSet []any

// Match returns true if the request matches all
// matchers in mset or if there are no matchers.
func (mset MatcherSet) Match(r *http.Request) bool {
	for _, m := range mset {
		if me, ok := m.(RequestMatcherWithError); ok {
			match, _ := me.MatchWithError(r)
			if !match {
				return false
			}
			continue
		}
		if me, ok := m.(RequestMatcher); ok {
			if !me.Match(r) {
				return false
			}
			continue
		}
		return false
	}
	return true
}

// MatchWithError returns true if r matches m.
func (mset MatcherSet) MatchWithError(r *http.Request) (bool, error) {
	for _, m := range mset {
		if me, ok := m.(RequestMatcherWithError); ok {
			match, err := me.MatchWithError(r)
			if err != nil || !match {
				return match, err
			}
			continue
		}
		if me, ok := m.(RequestMatcher); ok {
			if !me.Match(r) {
				// for backwards compatibility
				err, ok := GetVar(r.Context(), MatcherErrorVarKey).(error)
				if ok {
					// clear out the error from context since we've consumed it
					SetVar(r.Context(), MatcherErrorVarKey, nil)
					return false, err
				}
				return false, nil
			}
			continue
		}
		return false, fmt.Errorf("matcher is not a RequestMatcher or RequestMatcherWithError: %#v", m)
	}
	return true, nil
}

// RawMatcherSets is a group of matcher sets
// in their raw, JSON form.
type RawMatcherSets []caddy.ModuleMap

// MatcherSets is a group of matcher sets capable
// of checking whether a request matches any of
// the sets.
type MatcherSets []MatcherSet

// AnyMatch returns true if req matches any of the
// matcher sets in ms or if there are no matchers,
// in which case the request always matches.
//
// Deprecated: Use AnyMatchWithError instead.
func (ms MatcherSets) AnyMatch(req *http.Request) bool {
	for _, m := range ms {
		match, err := m.MatchWithError(req)
		if err != nil {
			SetVar(req.Context(), MatcherErrorVarKey, err)
			return false
		}
		if match {
			return match
		}
	}
	return len(ms) == 0
}

// AnyMatchWithError returns true if req matches any of the
// matcher sets in ms or if there are no matchers, in which
// case the request always matches. If any matcher returns
// an error, we cut short and return the error.
func (ms MatcherSets) AnyMatchWithError(req *http.Request) (bool, error) {
	for _, m := range ms {
		match, err := m.MatchWithError(req)
		if err != nil || match {
			return match, err
		}
	}
	return len(ms) == 0, nil
}

// FromInterface fills ms from an 'any' value obtained from LoadModule.
func (ms *MatcherSets) FromInterface(matcherSets any) error {
	for _, matcherSetIfaces := range matcherSets.([]map[string]any) {
		var matcherSet MatcherSet
		for _, matcher := range matcherSetIfaces {
			if m, ok := matcher.(RequestMatcherWithError); ok {
				matcherSet = append(matcherSet, m)
				continue
			}
			if m, ok := matcher.(RequestMatcher); ok {
				matcherSet = append(matcherSet, m)
				continue
			}
			return fmt.Errorf("decoded module is not a RequestMatcher or RequestMatcherWithError: %#v", matcher)
		}
		*ms = append(*ms, matcherSet)
	}
	return nil
}

// TODO: Is this used?
func (ms MatcherSets) String() string {
	result := "["
	for _, matcherSet := range ms {
		for _, matcher := range matcherSet {
			result += fmt.Sprintf(" %#v", matcher)
		}
	}
	return result + " ]"
}

var routeGroupCtxKey = caddy.CtxKey("route_group")
