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
	"io"
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

	// With a single provider there is nothing to isolate it from, so it is
	// given the real ResponseWriter directly — no buffering, and every writer
	// capability (Flusher, Hijacker, Pusher, ReaderFrom, ...) is preserved
	// exactly as before. Only when MULTIPLE providers are configured can a
	// failing provider's response clobber another provider's or the successful
	// handler chain's, so there each provider gets its own bounded buffered
	// writer. See https://github.com/caddyserver/caddy/issues/5190.
	isolate := len(a.Providers) > 1

	var winner *bufferedResponseWriter
	var failed []*bufferedResponseWriter
	for provName, prov := range a.Providers {
		pw := w
		var bw *bufferedResponseWriter
		if isolate {
			bw = newBufferedResponseWriter(w)
			pw = bw
		}
		user, authed, err = prov.Authenticate(pw, r)
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
		if isolate {
			failed = append(failed, bw)
		}
		if userHasInfo(user) {
			candidate = user
			hasCandidate = true
		}
	}
	if !authed {
		if hasCandidate {
			setAuthUserPlaceholders(repl, "http.auth.candidate", candidate)
		}
		// When isolating, no failed provider's response reached the real
		// writer, so apply one provider's challenge headers (e.g. a
		// WWW-Authenticate, or a Location); a redirecting provider takes
		// precedence and is sent as a full response. A single provider already
		// wrote its challenge directly to the real writer. Either way, fall
		// through to the auth error so handle_errors runs and a challenge that
		// set only headers (like basic auth) still returns 401, not 200.
		if isolate {
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
		}
		return caddyhttp.Error(http.StatusUnauthorized, fmt.Errorf("not authenticated"))
	}

	// When isolating, the winning provider wrote to its buffer; copy the
	// headers it set (e.g. a Set-Cookie establishing a new session) onto the
	// real writer. Its status/body are NOT replayed: the request is
	// authenticated and continues down the handler chain, which produces the
	// actual response. (A single provider already wrote its headers directly.)
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

// maxBufferedAuthResponse caps how much of a single provider's response body
// is buffered during multi-provider authentication, so a misbehaving provider
// cannot cause unbounded memory use. Authentication challenges are tiny; this
// limit is far larger than any legitimate challenge.
const maxBufferedAuthResponse = 1 << 20 // 1 MiB

// bufferedResponseWriter captures a single provider's response — headers,
// status, and a size-capped body — so it can be discarded or replayed once
// the outcome of the whole provider set is known (only used when more than
// one provider is configured). It embeds caddyhttp.ResponseWriterWrapper so
// the underlying writer's capabilities (Pusher/ReaderFrom, and Flusher/
// Hijacker via http.ResponseController) remain type-assertable; body writes,
// however, are captured rather than streamed, and Flush is suppressed while
// buffering. A provider that hijacks the connection mid-authentication
// escapes to the real writer (isolation cannot apply once hijacked); auth
// providers are not expected to stream or hijack during Authenticate.
type bufferedResponseWriter struct {
	*caddyhttp.ResponseWriterWrapper
	header     http.Header
	statusCode int
	buf        bytes.Buffer
	overflowed bool
}

func newBufferedResponseWriter(w http.ResponseWriter) *bufferedResponseWriter {
	return &bufferedResponseWriter{
		ResponseWriterWrapper: &caddyhttp.ResponseWriterWrapper{ResponseWriter: w},
		header:                make(http.Header),
	}
}

func (bw *bufferedResponseWriter) Header() http.Header { return bw.header }

func (bw *bufferedResponseWriter) WriteHeader(statusCode int) {
	if bw.statusCode == 0 {
		bw.statusCode = statusCode
	}
}

func (bw *bufferedResponseWriter) Write(data []byte) (int, error) {
	bw.WriteHeader(http.StatusOK)
	if room := maxBufferedAuthResponse - bw.buf.Len(); room < len(data) {
		bw.overflowed = true
		if room > 0 {
			bw.buf.Write(data[:room])
		}
		// Report a full write so the provider does not error; the body is a
		// discardable challenge and only its capped prefix is retained.
		return len(data), nil
	}
	return bw.buf.Write(data)
}

// ReadFrom captures the body (respecting the size cap) instead of the
// embedded wrapper's pass-through to the real writer, which would leak the
// provider's body past isolation. It returns the total number of bytes
// consumed from r — retained and drained alike — and any read error,
// per the io.ReaderFrom contract.
func (bw *bufferedResponseWriter) ReadFrom(r io.Reader) (int64, error) {
	bw.WriteHeader(http.StatusOK)
	room := int64(maxBufferedAuthResponse - bw.buf.Len())
	n, err := bw.buf.ReadFrom(io.LimitReader(r, room))
	if err != nil {
		return n, err
	}
	extra, err := io.Copy(io.Discard, r)
	if extra > 0 {
		bw.overflowed = true
	}
	return n + extra, err
}

// FlushError suppresses flushing while a provider's response is buffered, so a
// provider that flushes during Authenticate cannot prematurely commit the
// response to the client (http.ResponseController.Flush uses this).
func (bw *bufferedResponseWriter) FlushError() error { return nil }

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
