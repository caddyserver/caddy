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

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestAuthenticationSetsUserPlaceholdersOnUnauthorized(t *testing.T) {
	repl := caddy.NewReplacer()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl))

	a := Authentication{
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
	}

	nextCalled := false
	err := a.ServeHTTP(httptest.NewRecorder(), req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		nextCalled = true
		return nil
	}))
	if err == nil {
		t.Fatal("expected unauthorized error")
	}

	var handlerErr caddyhttp.HandlerError
	if !errors.As(err, &handlerErr) {
		t.Fatalf("expected caddyhttp.HandlerError, got %T", err)
	}
	if handlerErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, handlerErr.StatusCode)
	}
	if nextCalled {
		t.Fatal("next handler was called")
	}

	if got, ok := repl.GetString("http.auth.user.id"); !ok || got != "alice" {
		t.Fatalf("expected http.auth.user.id to be alice, got %q (ok=%v)", got, ok)
	}
	if got, ok := repl.GetString("http.auth.user.role"); !ok || got != "admin" {
		t.Fatalf("expected http.auth.user.role to be admin, got %q (ok=%v)", got, ok)
	}
}

type staticAuthenticator struct {
	user   User
	authed bool
	err    error
}

func (s staticAuthenticator) Authenticate(http.ResponseWriter, *http.Request) (User, bool, error) {
	return s.user, s.authed, s.err
}
