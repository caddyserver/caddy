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

package caddyauth

import (
	"fmt"
	"log"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(Authentication{})
}

// Authentication is a middleware which provides user authentication.
type Authentication struct {
	ProvidersRaw caddy.ModuleMap `json:"providers,omitempty" caddy:"namespace=http.authentication.providers"`

	Providers map[string]Authenticator `json:"-"`
}

// CaddyModule returns the Caddy module information.
func (Authentication) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.authentication",
		New: func() caddy.Module { return new(Authentication) },
	}
}

// Provision sets up a.
func (a *Authentication) Provision(ctx caddy.Context) error {
	a.Providers = make(map[string]Authenticator)
	mods, err := ctx.LoadModule(a, "ProvidersRaw")
	if err != nil {
		return fmt.Errorf("loading authentication providers: %v", err)
	}
	for modName, modIface := range mods.(map[string]interface{}) {
		a.Providers[modName] = modIface.(Authenticator)
	}
	return nil
}

func (a Authentication) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	var user User
	var authed bool
	var err error
	for provName, prov := range a.Providers {
		user, authed, err = prov.Authenticate(w, r)
		if err != nil {
			log.Printf("[ERROR] Authenticating with %s: %v", provName, err)
			continue
		}
		if authed {
			break
		}
	}
	if !authed {
		return caddyhttp.Error(http.StatusUnauthorized, fmt.Errorf("not authenticated"))
	}

	repl := r.Context().Value(caddy.ReplacerCtxKey).(caddy.Replacer)
	repl.Set("http.authentication.user.id", user.ID)

	return next.ServeHTTP(w, r)
}

// Authenticator is a type which can authenticate a request.
// If a request was not authenticated, it returns false. An
// error is only returned if authenticating the request fails
// for a technical reason (not for bad/missing credentials).
type Authenticator interface {
	Authenticate(http.ResponseWriter, *http.Request) (User, bool, error)
}

// User represents an authenticated user.
type User struct {
	ID string
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Authentication)(nil)
	_ caddyhttp.MiddlewareHandler = (*Authentication)(nil)
)
