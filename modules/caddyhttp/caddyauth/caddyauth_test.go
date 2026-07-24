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
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestAuthenticationRejectedUserSetsCandidatePlaceholders(t *testing.T) {
	auth := Authentication{
		Providers: map[string]Authenticator{
			"test": staticAuthenticator{
				user: User{
					ID: "alice",
					Metadata: map[string]string{
						"role": "admin",
					},
				},
			},
		},
		logger: zap.NewNop(),
	}
	req, repl := newRequestWithReplacer()
	nextCalled := false

	err := auth.ServeHTTP(httptest.NewRecorder(), req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		nextCalled = true
		return nil
	}))
	if err == nil {
		t.Fatal("expected authentication error")
	}
	var handlerErr caddyhttp.HandlerError
	if !errors.As(err, &handlerErr) {
		t.Fatalf("expected HandlerError, got %T", err)
	}
	if handlerErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, handlerErr.StatusCode)
	}
	if nextCalled {
		t.Fatal("next handler was called for rejected authentication")
	}

	assertPlaceholder(t, repl, "http.auth.candidate.id", "alice")
	assertPlaceholder(t, repl, "http.auth.candidate.role", "admin")
	assertPlaceholderAbsent(t, repl, "http.auth.user.id")
	assertPlaceholderAbsent(t, repl, "http.auth.user.role")
}

func TestAuthenticationSuccessfulUserSetsUserPlaceholdersOnly(t *testing.T) {
	auth := Authentication{
		Providers: map[string]Authenticator{
			"test": staticAuthenticator{
				user: User{
					ID: "alice",
					Metadata: map[string]string{
						"role": "admin",
					},
				},
				authed: true,
			},
		},
		logger: zap.NewNop(),
	}
	req, repl := newRequestWithReplacer()
	nextCalled := false

	err := auth.ServeHTTP(httptest.NewRecorder(), req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		nextCalled = true
		return nil
	}))
	if err != nil {
		t.Fatalf("expected no authentication error, got %v", err)
	}
	if !nextCalled {
		t.Fatal("next handler was not called for successful authentication")
	}

	assertPlaceholder(t, repl, "http.auth.user.id", "alice")
	assertPlaceholder(t, repl, "http.auth.user.role", "admin")
	assertPlaceholderAbsent(t, repl, "http.auth.candidate.id")
	assertPlaceholderAbsent(t, repl, "http.auth.candidate.role")
}

func TestAuthenticationSuccessfulProviderDoesNotExposeEarlierCandidate(t *testing.T) {
	auth := Authentication{
		Providers: map[string]Authenticator{
			"first": staticAuthenticator{
				user: User{
					ID: "rejected",
					Metadata: map[string]string{
						"role": "guest",
					},
				},
			},
			"second": staticAuthenticator{
				user: User{
					ID: "accepted",
					Metadata: map[string]string{
						"role": "admin",
					},
				},
				authed: true,
			},
		},
		logger: zap.NewNop(),
	}
	req, repl := newRequestWithReplacer()

	err := auth.ServeHTTP(httptest.NewRecorder(), req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		return nil
	}))
	if err != nil {
		t.Fatalf("expected no authentication error, got %v", err)
	}

	assertPlaceholder(t, repl, "http.auth.user.id", "accepted")
	assertPlaceholder(t, repl, "http.auth.user.role", "admin")
	assertPlaceholderAbsent(t, repl, "http.auth.candidate.id")
	assertPlaceholderAbsent(t, repl, "http.auth.candidate.role")
}

func TestAuthenticationRejectedEmptyUserDoesNotSetCandidatePlaceholders(t *testing.T) {
	auth := Authentication{
		Providers: map[string]Authenticator{
			"test": staticAuthenticator{},
		},
		logger: zap.NewNop(),
	}
	req, repl := newRequestWithReplacer()

	err := auth.ServeHTTP(httptest.NewRecorder(), req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		t.Fatal("next handler was called for rejected authentication")
		return nil
	}))
	if err == nil {
		t.Fatal("expected authentication error")
	}

	assertPlaceholderAbsent(t, repl, "http.auth.candidate.id")
}

func newRequestWithReplacer() (*http.Request, *caddy.Replacer) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	repl := caddy.NewReplacer()
	ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
	return req.WithContext(ctx), repl
}

func assertPlaceholder(t *testing.T, repl *caddy.Replacer, key, expected string) {
	t.Helper()
	actual, ok := repl.GetString(key)
	if !ok {
		t.Fatalf("expected placeholder %q to be set", key)
	}
	if actual != expected {
		t.Fatalf("expected placeholder %q to be %q, got %q", key, expected, actual)
	}
}

func assertPlaceholderAbsent(t *testing.T, repl *caddy.Replacer, key string) {
	t.Helper()
	if actual, ok := repl.GetString(key); ok {
		t.Fatalf("expected placeholder %q to be absent, got %q", key, actual)
	}
}

type staticAuthenticator struct {
	user   User
	authed bool
	err    error
}

func (a staticAuthenticator) Authenticate(http.ResponseWriter, *http.Request) (User, bool, error) {
	return a.user, a.authed, a.err
}

// writingAuthenticator writes to the response during Authenticate (as a real
// provider might: a challenge/redirect on failure, a Set-Cookie on success).
type writingAuthenticator struct {
	authed bool
	write  func(w http.ResponseWriter)
}

func (a writingAuthenticator) Authenticate(w http.ResponseWriter, _ *http.Request) (User, bool, error) {
	if a.write != nil {
		a.write(w)
	}
	if a.authed {
		return User{ID: "u"}, true, nil
	}
	return User{}, false, nil
}

func serveAuth(providers map[string]Authenticator, next caddyhttp.Handler) *httptest.ResponseRecorder {
	a := Authentication{Providers: providers, logger: zap.NewNop()}
	req, _ := newRequestWithReplacer()
	rr := httptest.NewRecorder()
	_ = a.ServeHTTP(rr, req, next)
	return rr
}

// A failing provider that writes a redirect must not clobber the response
// when another provider authenticates the request. Provider map iteration
// order is randomized, so exercise both orderings. #5190
func TestFailingProviderDoesNotClobberSuccess(t *testing.T) {
	redirecter := writingAuthenticator{write: func(w http.ResponseWriter) {
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
	}}
	succeeder := writingAuthenticator{authed: true}

	for i := 0; i < 20; i++ {
		reached := false
		rr := serveAuth(map[string]Authenticator{
			"redirect": redirecter, "succeed": succeeder,
		}, caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
			reached = true
			w.WriteHeader(http.StatusOK)
			return nil
		}))
		if !reached {
			t.Fatalf("run %d: handler chain not reached despite successful auth", i)
		}
		if rr.Code != http.StatusOK {
			t.Fatalf("run %d: got status %d, want 200 (failing provider leaked its redirect)", i, rr.Code)
		}
		if loc := rr.Header().Get("Location"); loc != "" {
			t.Fatalf("run %d: failing provider's Location header leaked: %q", i, loc)
		}
	}
}

// The successful provider's headers (e.g. a Set-Cookie for a new session)
// must reach the client even though its response is otherwise buffered. #5190
func TestSuccessfulProviderHeadersPreserved(t *testing.T) {
	succeeder := writingAuthenticator{authed: true, write: func(w http.ResponseWriter) {
		w.Header().Set("Set-Cookie", "session=abc; Path=/")
	}}
	rr := serveAuth(map[string]Authenticator{"succeed": succeeder},
		caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
			w.WriteHeader(http.StatusOK)
			return nil
		}))
	if got := rr.Header().Get("Set-Cookie"); got != "session=abc; Path=/" {
		t.Fatalf("successful provider's Set-Cookie not preserved: got %q", got)
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200", rr.Code)
	}
}

// When every provider fails, a challenge still reaches the client and a
// redirect takes precedence over a plain failure. #5190
func TestAllFailReplaysRedirect(t *testing.T) {
	plain := writingAuthenticator{write: func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusUnauthorized)
	}}
	redirecter := writingAuthenticator{write: func(w http.ResponseWriter) {
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
	}}
	rr := serveAuth(map[string]Authenticator{
		"plain": plain, "redirect": redirecter,
	}, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		t.Fatal("handler chain must not run when auth fails")
		return nil
	}))
	if rr.Code != http.StatusFound {
		t.Fatalf("got status %d, want 302 (redirect should win the replay)", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "/login" {
		t.Fatalf("redirect Location not replayed: %q", loc)
	}
}

// A provider that fails by setting only a challenge header (no status/body) —
// which is exactly what basic auth does (WWW-Authenticate) — must still result
// in a 401 with that header, not a 200. #5190
func TestHeaderOnlyChallengeStillReturns401(t *testing.T) {
	basicish := writingAuthenticator{write: func(w http.ResponseWriter) {
		w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
	}}
	err := (func() error {
		a := Authentication{Providers: map[string]Authenticator{"basic": basicish}, logger: zap.NewNop()}
		req, _ := newRequestWithReplacer()
		return a.ServeHTTP(&recordingStatusWriter{ResponseWriter: httptest.NewRecorder()}, req,
			caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
				t.Fatal("handler chain must not run when auth fails")
				return nil
			}))
	})()
	var handlerErr caddyhttp.HandlerError
	if !errors.As(err, &handlerErr) {
		t.Fatalf("expected a 401 HandlerError, got %v (a header-only challenge must not return nil/200)", err)
	}
	if handlerErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", handlerErr.StatusCode)
	}
}

// recordingStatusWriter records whether WriteHeader was called and with what
// status, to prove a header-only challenge does not emit a 200.
type recordingStatusWriter struct {
	http.ResponseWriter
	wroteHeader bool
	status      int
}

func (rw *recordingStatusWriter) WriteHeader(status int) {
	rw.wroteHeader = true
	rw.status = status
	rw.ResponseWriter.WriteHeader(status)
}
