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

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
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
// If authentication is rejected but a provider returns user information,
// the placeholder `{http.auth.candidate.id}` will be set to the candidate
// username, and also `{http.auth.candidate.*}` placeholders may be set
// for candidate user metadata. Candidate placeholders do not represent a
// successfully authenticated principal.
//
// In case of an error, the placeholder `{http.auth.<provider>.error}`
// will be set to the error message returned by the authentication
// provider.
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

// Provision sets up an Authentication module by initializing its logger,
// loading and registering all configured authentication providers.
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
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	var user User
	var candidate User
	var hasCandidate bool
	var authed bool
	var err error
	var winner *bufferedResponseWriter
	var failed []*bufferedResponseWriter
	for provName, prov := range a.Providers {
		// Give each provider its own buffered response writer so that a
		// provider which writes to the response (e.g. a failing provider
		// that sends a 401 challenge or a login redirect) cannot clobber
		// the response of another provider or of the successful handler
		// chain. The winning provider's headers are applied; failed
		// providers' responses are discarded unless every provider fails.
		// See https://github.com/caddyserver/caddy/issues/5190.
		bw := &bufferedResponseWriter{header: make(http.Header)}
		user, authed, err = prov.Authenticate(bw, r)
		if err != nil {
			if c := a.logger.Check(zapcore.ErrorLevel, "auth provider returned error"); c != nil {
				c.Write(zap.String("provider", provName), zap.Error(err))
			}
			// Set the error from the authentication provider in a placeholder,
			// so it can be used in the handle_errors directive.
			repl.Set("http.auth."+provName+".error", err.Error())
			continue
		}
		if authed {
			winner = bw
			break
		}
		failed = append(failed, bw)
		if userHasInfo(user) {
			candidate = user
			hasCandidate = true
		}
	}
	if !authed {
		if hasCandidate {
			setAuthUserPlaceholders(repl, "http.auth.candidate", candidate)
		}
		// No provider authenticated the request. Apply the challenge headers
		// (e.g. WWW-Authenticate, or a Location) of one provider that tried,
		// so a meaningful challenge still reaches the client without other
		// providers clobbering it; a redirecting provider takes precedence.
		// A provider that produced a full redirect response is sent as-is;
		// otherwise we fall through to the auth error so handle_errors runs
		// and the client still receives a 401 — a challenge that set only
		// headers (like basic auth) must NOT downgrade the status to 200.
		if replay := pickReplay(failed); replay != nil {
			for field, vals := range replay.header {
				w.Header()[field] = vals
			}
			if replay.statusCode >= 300 && replay.statusCode < 400 {
				w.WriteHeader(replay.statusCode)
				_, _ = w.Write(replay.buf.Bytes())
				return nil
			}
		}
		return caddyhttp.Error(http.StatusUnauthorized, fmt.Errorf("not authenticated"))
	}

	// The successful provider may have set headers that must reach the
	// client (e.g. a Set-Cookie establishing a new session), so copy its
	// headers onto the real writer. Its status and body are NOT replayed:
	// the request is authenticated and continues down the handler chain,
	// which produces the actual response.
	if winner != nil {
		for field, vals := range winner.header {
			w.Header()[field] = vals
		}
	}

	setAuthUserPlaceholders(repl, "http.auth.user", user)

	return next.ServeHTTP(w, r)
}

// pickReplay chooses which failed provider's buffered response to send when
// no provider authenticated: a redirect (3xx) wins, otherwise the first
// provider that wrote anything (status, body, or headers).
func pickReplay(failed []*bufferedResponseWriter) *bufferedResponseWriter {
	var replay *bufferedResponseWriter
	for _, bw := range failed {
		if bw.statusCode >= 300 && bw.statusCode < 400 {
			return bw
		}
		if replay == nil && (bw.statusCode != 0 || bw.buf.Len() > 0 || len(bw.header) > 0) {
			replay = bw
		}
	}
	return replay
}

func userHasInfo(user User) bool {
	return user.ID != "" || len(user.Metadata) > 0
}

// bufferedResponseWriter captures a single provider's response — headers,
// status, and body — so it can be discarded or replayed once the outcome of
// the whole provider set is known. Providers that need to stream (Flush) or
// hijack the connection during authentication are not supported while
// buffered; authentication providers are not expected to do so.
type bufferedResponseWriter struct {
	header     http.Header
	statusCode int
	buf        bytes.Buffer
}

func (bw *bufferedResponseWriter) Header() http.Header { return bw.header }

func (bw *bufferedResponseWriter) WriteHeader(statusCode int) {
	if bw.statusCode == 0 {
		bw.statusCode = statusCode
	}
}

func (bw *bufferedResponseWriter) Write(data []byte) (int, error) {
	bw.WriteHeader(http.StatusOK)
	return bw.buf.Write(data)
}

func setAuthUserPlaceholders(repl *caddy.Replacer, namespace string, user User) {
	repl.Set(namespace+".id", user.ID)
	for k, v := range user.Metadata {
		repl.Set(namespace+"."+k, v)
	}
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
