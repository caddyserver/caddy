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
