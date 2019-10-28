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
	caddy.RegisterModule(Subroute{})
}

// Subroute implements a handler that compiles and executes routes.
// This is useful for a batch of routes that all inherit the same
// matchers, or for routes with matchers that must be have deferred
// evaluation (e.g. if they depend on placeholders created by other
// matchers that need to be evaluated first).
//
// You can also use subroutes to handle errors from specific handlers.
// First the primary Routes will be executed, and if they return an
// error, the Errors routes will be executed; in that case, an error
// is only returned to the entry point at the server if there is an
// additional error returned from the errors routes.
type Subroute struct {
	Routes RouteList        `json:"routes,omitempty"`
	Errors *HTTPErrorConfig `json:"errors,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (Subroute) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		Name: "http.handlers.subroute",
		New:  func() caddy.Module { return new(Subroute) },
	}
}

// Provision sets up subrouting.
func (sr *Subroute) Provision(ctx caddy.Context) error {
	if sr.Routes != nil {
		err := sr.Routes.Provision(ctx)
		if err != nil {
			return fmt.Errorf("setting up subroutes: %v", err)
		}
		if sr.Errors != nil {
			err := sr.Errors.Routes.Provision(ctx)
			if err != nil {
				return fmt.Errorf("setting up error subroutes: %v", err)
			}
		}
	}
	return nil
}

func (sr *Subroute) ServeHTTP(w http.ResponseWriter, r *http.Request, _ Handler) error {
	subroute := sr.Routes.BuildCompositeRoute(r)
	err := subroute.ServeHTTP(w, r)
	if err != nil && sr.Errors != nil {
		r = sr.Errors.WithError(r, err)
		errRoute := sr.Errors.Routes.BuildCompositeRoute(r)
		return errRoute.ServeHTTP(w, r)
	}
	return err
}

// Interface guards
var (
	_ caddy.Provisioner = (*Subroute)(nil)
	_ MiddlewareHandler = (*Subroute)(nil)
)
