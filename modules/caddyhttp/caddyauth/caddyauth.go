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
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Authentication{})
}

// Authentication is a middleware which provides user authentication.
// Rejects requests with HTTP 401 if the request is not authenticated.
//
// Its API is still experimental and may be subject to change.
type Authentication struct {
	// A set of authentication providers. If none are specified,
	// all requests will always be unauthenticated.
	ProvidersRaw caddy.ModuleMap `json:"providers,omitempty" caddy:"namespace=http.authentication.providers"`

	Providers map[string]Authenticator `json:"-"`

	logger *zap.Logger
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
	a.logger = ctx.Logger(a)
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
	logger := a.logger.With(zap.Object("request", caddyhttp.LoggableHTTPRequest{Request: r}))
	for provName, prov := range a.Providers {
		user, authed, err = prov.Authenticate(w, r)
		if err != nil {
			logger.Error("could not check authentication",
				zap.String("provider", provName),
				zap.Error(err))
			continue
		}
		if authed {
			break
		}
		logger.Warn("failed authentication", zap.String("provider", provName))
	}
	if !authed {
		return caddyhttp.Error(http.StatusUnauthorized, fmt.Errorf("not authenticated"))
	}

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	repl.Set("http.auth.user.id", user.ID)
	for k, v := range user.Metadata {
		repl.Set("http.auth.user."+k, v)
	}

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
	// The ID of the authenticated user.
	ID string

	// Any other relevant data about this
	// user. Keys should be adhere to Caddy
	// conventions (snake_casing), as all
	// keys will be made available as
	// placeholders.
	Metadata map[string]string
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Authentication)(nil)
	_ caddyhttp.MiddlewareHandler = (*Authentication)(nil)
)
