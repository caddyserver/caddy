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
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

func newVarsTestRequest(t *testing.T, target string, headers http.Header, vars map[string]any) (*http.Request, *caddy.Replacer) {
	t.Helper()

	if target == "" {
		target = "https://example.com/test"
	}

	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Header = headers

	repl := caddy.NewReplacer()
	ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
	if vars == nil {
		vars = make(map[string]any)
	}
	// Inject vars directly so these tests exercise matcher-side handling of
	// already-resolved values, not VarsMiddleware placeholder expansion.
	ctx = context.WithValue(ctx, VarsCtxKey, vars)
	req = req.WithContext(ctx)

	addHTTPVarsToReplacer(repl, req, httptest.NewRecorder())

	return req, repl
}

func TestVarsMatcherDoesNotExpandResolvedValues(t *testing.T) {
	t.Setenv("CADDY_VARS_TEST_SECRET", "topsecret")

	for _, tc := range []struct {
		name    string
		target  string
		match   VarsMatcher
		headers http.Header
		vars    map[string]any
		expect  bool
	}{
		{
			name:   "literal variable value containing placeholder syntax is not re-expanded",
			match:  VarsMatcher{"secret": []string{"topsecret"}},
			vars:   map[string]any{"secret": "{env.CADDY_VARS_TEST_SECRET}"},
			expect: false,
		},
		{
			name:    "placeholder key value containing placeholder syntax is not re-expanded",
			match:   VarsMatcher{"{http.request.header.X-Input}": []string{"topsecret"}},
			headers: http.Header{"X-Input": []string{"{env.CADDY_VARS_TEST_SECRET}"}},
			expect:  false,
		},
		{
			name:   "query placeholder value containing placeholder syntax is not re-expanded",
			target: "https://example.com/test?foo=%7Benv.CADDY_VARS_TEST_SECRET%7D",
			match:  VarsMatcher{"{http.request.uri.query.foo}": []string{"topsecret"}},
			expect: false,
		},
		{
			name:   "matcher values still expand placeholders",
			match:  VarsMatcher{"secret": []string{"{env.CADDY_VARS_TEST_SECRET}"}},
			vars:   map[string]any{"secret": "topsecret"},
			expect: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req, _ := newVarsTestRequest(t, tc.target, tc.headers, tc.vars)

			actual, err := tc.match.MatchWithError(req)
			if err != nil {
				t.Fatalf("MatchWithError() error = %v", err)
			}

			if actual != tc.expect {
				t.Fatalf("MatchWithError() = %t, want %t", actual, tc.expect)
			}
		})
	}
}

func TestMatchVarsREDoesNotExpandResolvedValues(t *testing.T) {
	t.Setenv("CADDY_VARS_TEST_SECRET", "topsecret")

	for _, tc := range []struct {
		name    string
		target  string
		match   MatchVarsRE
		headers http.Header
		vars    map[string]any
		expect  bool
	}{
		{
			name:   "literal variable value containing placeholder syntax is not re-expanded",
			match:  MatchVarsRE{"secret": &MatchRegexp{Pattern: "^topsecret$"}},
			vars:   map[string]any{"secret": "{env.CADDY_VARS_TEST_SECRET}"},
			expect: false,
		},
		{
			name:    "placeholder key value containing placeholder syntax is not re-expanded",
			match:   MatchVarsRE{"{http.request.header.X-Input}": &MatchRegexp{Pattern: "^topsecret$"}},
			headers: http.Header{"X-Input": []string{"{env.CADDY_VARS_TEST_SECRET}"}},
			expect:  false,
		},
		{
			name:   "query placeholder value containing placeholder syntax is not re-expanded",
			target: "https://example.com/test?foo=%7Benv.CADDY_VARS_TEST_SECRET%7D",
			match:  MatchVarsRE{"{http.request.uri.query.foo}": &MatchRegexp{Pattern: "^topsecret$"}},
			expect: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := tc.match.Provision(caddy.Context{})
			if err != nil {
				t.Fatalf("Provision() error = %v", err)
			}

			err = tc.match.Validate()
			if err != nil {
				t.Fatalf("Validate() error = %v", err)
			}

			req, _ := newVarsTestRequest(t, tc.target, tc.headers, tc.vars)

			actual, err := tc.match.MatchWithError(req)
			if err != nil {
				t.Fatalf("MatchWithError() error = %v", err)
			}

			if actual != tc.expect {
				t.Fatalf("MatchWithError() = %t, want %t", actual, tc.expect)
			}
		})
	}
}
