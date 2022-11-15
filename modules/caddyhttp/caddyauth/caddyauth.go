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
	"bytes"
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
// After a successful authentication, the placeholder
// `{http.auth.user.id}` will be set to the username, and also
// `{http.auth.user.*}` placeholders may be set for any authentication
// modules that provide user metadata.
//
// Its API is still experimental and may be subject to change.
type Authentication struct {
	// A set of authentication providers. If none are specified,
	// all requests will always be unauthenticated. If multiple
	// providers are specified only one needs to authenticate
	// successfully. In case all of them are unauthorized the reply
	// will be taken from any provider that redirects, if there is
	// no provider that redirects the reply of any provider is taken.
	// If you want multiple authentication providers that all need to succeed
	// you can create a chain of handlers.
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
	a.logger = ctx.Logger()
	a.Providers = make(map[string]Authenticator)
	mods, err := ctx.LoadModule(a, "ProvidersRaw")
	if err != nil {
		return fmt.Errorf("loading authentication providers: %v", err)
	}
	for modName, modIface := range mods.(map[string]any) {
		a.Providers[modName] = modIface.(Authenticator)
	}
	return nil
}

func (a Authentication) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	var user User
	var authed bool
	var err error
	// This code makes the following assumption: In case of multiple
	// authentication providers it is enough if one of them authenticates the
	// user for the whole authentication to succeed. In case all of the
	// providers fail to authenticate we write the reply of any of the providers
	// that redirect to the response writer, if there is no such provider the
	// response of any provider is written. We choose response of the
	// redirecting provider so that a login flow that relies on redirects works
	// correctly.
	responseWriters := make(map[string]caddyhttp.ResponseRecorder, len(a.Providers))
	for provName, prov := range a.Providers {
		// We always want to buffer the response because only once we have the
		// reply of all providers we can decide which one to actually use (if
		// any). Usually auth replies should be small enough.
		alwaysBuffer := func(status int, header http.Header) bool { return true }
		rw := caddyhttp.NewResponseRecorder(w, new(bytes.Buffer), alwaysBuffer)
		responseWriters[provName] = rw
		user, authed, err = prov.Authenticate(rw, r)
		if err != nil {
			a.logger.Error("auth provider returned error",
				zap.String("provider", provName),
				zap.Error(err))
			continue
		}
		if authed {
			break
		}
	}
	if !authed {
		// if we have any redirect we use the result from that.
		for provName, rw := range responseWriters {
			if rw.Status() < 300 || rw.Status() >= 400 {
				continue
			}
			if l := rw.Header().Get("Location"); l == "" {
				continue
			}
			if err := rw.WriteResponse(); err != nil {
				a.logger.Error("failed to write response from auth provider",
					zap.String("provider", provName),
					zap.Error(err),
				)
			}
			return caddyhttp.Error(http.StatusUnauthorized, fmt.Errorf("not authenticated"))
		}
		// no redirect choose a random reply.
		for provName, rw := range responseWriters {
			if err := rw.WriteResponse(); err != nil {
				a.logger.Error("failed to write response from auth provider",
					zap.String("provider", provName),
					zap.Error(err),
				)
			}
			break
		}
		return caddyhttp.Error(http.StatusUnauthorized, fmt.Errorf("not authenticated"))
	}

	// In case authentication was successful we don't care about any response
	// from the authentication handlers.

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
