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
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(caddy.Module{
		Name: "http.handlers.subroute",
		New:  func() interface{} { return new(Subroute) },
	})
}

// Subroute implements a handler that compiles and executes routes.
// This is useful for a batch of routes that all inherit the same
// matchers, or for routes with matchers that must be have deferred
// evaluation (e.g. if they depend on placeholders created by other
// matchers that need to be evaluated first).
type Subroute struct {
	Routes RouteList `json:"routes,omitempty"`
}

// Provision sets up subrouting.
func (sr *Subroute) Provision(ctx caddy.Context) error {
	if sr.Routes != nil {
		err := sr.Routes.Provision(ctx)
		if err != nil {
			return fmt.Errorf("setting up routes: %v", err)
		}
	}
	return nil
}

func (sr *Subroute) ServeHTTP(w http.ResponseWriter, r *http.Request, _ Handler) error {
	subroute := sr.Routes.BuildCompositeRoute(r)
	return subroute.ServeHTTP(w, r)
}

// Interface guards
var (
	_ caddy.Provisioner = (*Subroute)(nil)
	_ MiddlewareHandler = (*Subroute)(nil)
)
