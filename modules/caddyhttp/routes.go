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
	// route belongs. If a route belongs to a group, only
	// the first matching route in the group will be used.
	Group string `json:"group,omitempty"`

	// The matcher sets which will be used to qualify this
	// route for a request. Essentially the "if" statement
	// of this route. Each matcher set is OR'ed, but matchers
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

	// If true, no more routes will be executed after this one, even if they matched.
	Terminal bool `json:"terminal,omitempty"`

	// decoded values
	MatcherSets MatcherSets         `json:"-"`
	Handlers    []MiddlewareHandler `json:"-"`
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

// RouteList is a list of server routes that can
// create a middleware chain.
type RouteList []Route

// Provision sets up all the routes by loading the modules.
func (routes RouteList) Provision(ctx caddy.Context) error {
	for i, route := range routes {
		// matchers
		matchersIface, err := ctx.LoadModule(&route, "MatcherSetsRaw")
		if err != nil {
			return fmt.Errorf("loading matchers in route %d: %v", i, err)
		}
		err = routes[i].MatcherSets.FromInterface(matchersIface)
		if err != nil {
			return fmt.Errorf("route %d: %v", i, err)
		}

		// handlers
		handlersIface, err := ctx.LoadModule(&route, "HandlersRaw")
		if err != nil {
			return fmt.Errorf("loading handler modules in route %d: %v", i, err)
		}
		for _, handler := range handlersIface.([]interface{}) {
			routes[i].Handlers = append(routes[i].Handlers, handler.(MiddlewareHandler))
		}
	}
	return nil
}

// BuildCompositeRoute creates a chain of handlers by
// applying all of the matching routes.
func (routes RouteList) BuildCompositeRoute(req *http.Request) Handler {
	if len(routes) == 0 {
		return emptyHandler
	}

	var mid []Middleware
	groups := make(map[string]struct{})

	for _, route := range routes {
		// route must match at least one of the matcher sets
		if !route.MatcherSets.AnyMatch(req) {
			continue
		}

		// if route is part of a group, ensure only the
		// first matching route in the group is applied
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
		for _, mh := range route.Handlers {
			// we have to be sure to wrap mh outside
			// of our current stack frame so that the
			// reference to this mh isn't overwritten
			// on the next iteration, leaving the last
			// middleware in the chain as the ONLY
			// middleware in the chain!
			mid = append(mid, wrapMiddleware(mh))
		}

		// if this route is supposed to be last, don't
		// compile any more into the chain
		if route.Terminal {
			break
		}
	}

	// build the middleware chain, with the responder at the end
	stack := emptyHandler
	for i := len(mid) - 1; i >= 0; i-- {
		stack = mid[i](stack)
	}

	return stack
}

// wrapMiddleware wraps m such that it can be correctly
// appended to a list of middleware. We can't do this
// directly in a loop because it relies on a reference
// to mh not changing until the execution of its handler,
// which is deferred by multiple func closures. In other
// words, we need to pull this particular MiddlewareHandler
// pointer into its own stack frame to preserve it so it
// won't be overwritten in future loop iterations.
func wrapMiddleware(mh MiddlewareHandler) Middleware {
	return func(next HandlerFunc) HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) error {
			// TODO: We could wait to evaluate matchers here, just eval
			// the next matcher and choose the next route...

			// TODO: This is where request tracing could be implemented; also
			// see below to trace the responder as well
			// TODO: Trace a diff of the request, would be cool too! see what changed since the last middleware (host, headers, URI...)
			// TODO: see what the std lib gives us in terms of stack tracing too
			return mh.ServeHTTP(w, r, next)
		}
	}
}

// MatcherSet is a set of matchers which
// must all match in order for the request
// to be matched successfully.
type MatcherSet []RequestMatcher

// Match returns true if the request matches all
// matchers in mset.
func (mset MatcherSet) Match(r *http.Request) bool {
	for _, m := range mset {
		if !m.Match(r) {
			return false
		}
	}
	return true
}

// RawMatcherSets is a group of matcher sets
// in their raw, JSON form.
type RawMatcherSets []caddy.ModuleMap

// MatcherSets is a group of matcher sets capable
// of checking whether a request matches any of
// the sets.
type MatcherSets []MatcherSet

// AnyMatch returns true if req matches any of the
// matcher sets in mss or if there are no matchers,
// in which case the request always matches.
func (ms MatcherSets) AnyMatch(req *http.Request) bool {
	for _, m := range ms {
		if m.Match(req) {
			return true
		}
	}
	return len(ms) == 0
}

// FromInterface fills ms from an interface{} value obtained from LoadModule.
func (ms *MatcherSets) FromInterface(matcherSets interface{}) error {
	for _, matcherSetIfaces := range matcherSets.([]map[string]interface{}) {
		var matcherSet MatcherSet
		for _, matcher := range matcherSetIfaces {
			reqMatcher, ok := matcher.(RequestMatcher)
			if !ok {
				return fmt.Errorf("decoded module is not a RequestMatcher: %#v", matcher)
			}
			matcherSet = append(matcherSet, reqMatcher)
		}
		*ms = append(*ms, matcherSet)
	}
	return nil
}
