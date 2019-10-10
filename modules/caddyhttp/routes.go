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

// Route represents a set of matching rules,
// middlewares, and a responder for handling HTTP
// requests.
type Route struct {
	Group          string            `json:"group,omitempty"`
	MatcherSetsRaw RawMatcherSets    `json:"match,omitempty"`
	HandlersRaw    []json.RawMessage `json:"handle,omitempty"`
	Terminal       bool              `json:"terminal,omitempty"`

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
		matcherSets, err := route.MatcherSetsRaw.Setup(ctx)
		if err != nil {
			return err
		}
		routes[i].MatcherSets = matcherSets
		routes[i].MatcherSetsRaw = nil // allow GC to deallocate

		// handlers
		for j, rawMsg := range route.HandlersRaw {
			mh, err := ctx.LoadModuleInline("handler", "http.handlers", rawMsg)
			if err != nil {
				return fmt.Errorf("loading handler module in position %d: %v", j, err)
			}
			routes[i].Handlers = append(routes[i].Handlers, mh.(MiddlewareHandler))
		}
		routes[i].HandlersRaw = nil // allow GC to deallocate
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
type RawMatcherSets []map[string]json.RawMessage

// Setup sets up all matcher sets by loading each matcher module
// and returning the group of provisioned matcher sets.
func (rm RawMatcherSets) Setup(ctx caddy.Context) (MatcherSets, error) {
	if rm == nil {
		return nil, nil
	}
	var ms MatcherSets
	for _, matcherSet := range rm {
		var matchers MatcherSet
		for modName, rawMsg := range matcherSet {
			val, err := ctx.LoadModule("http.matchers."+modName, rawMsg)
			if err != nil {
				return nil, fmt.Errorf("loading matcher module '%s': %v", modName, err)
			}
			matchers = append(matchers, val.(RequestMatcher))
		}
		ms = append(ms, matchers)
	}
	return ms, nil
}

// MatcherSets is a group of matcher sets capable
// of checking whether a request matches any of
// the sets.
type MatcherSets []MatcherSet

// AnyMatch returns true if req matches any of the
// matcher sets in mss or if there are no matchers,
// in which case the request always matches.
func (mss MatcherSets) AnyMatch(req *http.Request) bool {
	for _, ms := range mss {
		if ms.Match(req) {
			return true
		}
	}
	return len(mss) == 0
}
