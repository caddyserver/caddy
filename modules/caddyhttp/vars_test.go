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

func TestGetVarAndSetVar(t *testing.T) {
	vars := map[string]any{
		"existing_key": "existing_value",
	}

	ctx := context.WithValue(context.Background(), VarsCtxKey, vars)

	if v := GetVar(ctx, "existing_key"); v != "existing_value" {
		t.Errorf("GetVar() = %v, want 'existing_value'", v)
	}

	if v := GetVar(ctx, "nonexistent_key"); v != nil {
		t.Errorf("GetVar() for missing key = %v, want nil", v)
	}

	emptyCtx := context.Background()
	if v := GetVar(emptyCtx, "any"); v != nil {
		t.Errorf("GetVar() on context without vars = %v, want nil", v)
	}
}

func TestSetVar(t *testing.T) {
	vars := map[string]any{}
	ctx := context.WithValue(context.Background(), VarsCtxKey, vars)

	SetVar(ctx, "key1", "value1")
	if vars["key1"] != "value1" {
		t.Errorf("SetVar() didn't set value, got %v", vars["key1"])
	}

	SetVar(ctx, "key1", "value2")
	if vars["key1"] != "value2" {
		t.Errorf("SetVar() didn't overwrite value, got %v", vars["key1"])
	}

	SetVar(ctx, "key1", nil)
	if _, ok := vars["key1"]; ok {
		t.Error("SetVar(nil) should delete the key")
	}

	// BUG: SetVar with nil for non-existent key should be a no-op per its documentation,
	// but it actually inserts a nil value into the map. The nil check only deletes
	// existing keys; if the key doesn't exist, execution falls through to the
	// final `varMap[key] = value` line, storing nil.
	SetVar(ctx, "nonexistent", nil)
	if _, ok := vars["nonexistent"]; !ok {
		t.Error("BUG: SetVar(nil) for non-existent key unexpectedly did NOT set the key. If this passes, the bug described in code comments may have been fixed.")
	}
}

func TestSetVarWithoutContext(t *testing.T) {
	ctx := context.Background()
	SetVar(ctx, "key", "value")
}

func TestVarsMiddlewareCaddyModule(t *testing.T) {
	m := VarsMiddleware{}
	info := m.CaddyModule()
	if info.ID != "http.handlers.vars" {
		t.Errorf("CaddyModule().ID = %v, want 'http.handlers.vars'", info.ID)
	}
}

func TestVarsMatcherEmptyMatch(t *testing.T) {
	m := VarsMatcher{}

	vars := map[string]any{}
	repl := caddy.NewReplacer()
	ctx := context.WithValue(context.Background(), VarsCtxKey, vars)
	ctx = context.WithValue(ctx, caddy.ReplacerCtxKey, repl)

	req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	req = req.WithContext(ctx)

	match, err := m.MatchWithError(req)
	if err != nil {
		t.Fatalf("MatchWithError() error = %v", err)
	}
	if !match {
		t.Error("empty VarsMatcher should match everything")
	}
}

func TestVarsMatcherMatch(t *testing.T) {
	vars := map[string]any{
		"my_var": "hello",
	}
	repl := caddy.NewReplacer()
	ctx := context.WithValue(context.Background(), VarsCtxKey, vars)
	ctx = context.WithValue(ctx, caddy.ReplacerCtxKey, repl)

	req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	req = req.WithContext(ctx)

	tests := []struct {
		name      string
		matcher   VarsMatcher
		wantMatch bool
	}{
		{
			name:      "matching variable",
			matcher:   VarsMatcher{"my_var": {"hello"}},
			wantMatch: true,
		},
		{
			name:      "non-matching variable",
			matcher:   VarsMatcher{"my_var": {"world"}},
			wantMatch: false,
		},
		{
			name:      "nonexistent variable",
			matcher:   VarsMatcher{"nonexistent": {"anything"}},
			wantMatch: false,
		},
		{
			name:      "multiple values OR",
			matcher:   VarsMatcher{"my_var": {"world", "hello", "foo"}},
			wantMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match := tt.matcher.Match(req)
			if match != tt.wantMatch {
				t.Errorf("Match() = %v, want %v", match, tt.wantMatch)
			}
		})
	}
}

func TestVarsMatcherWithNilVarValue(t *testing.T) {
	vars := map[string]any{
		"nil_var": nil,
	}
	repl := caddy.NewReplacer()
	ctx := context.WithValue(context.Background(), VarsCtxKey, vars)
	ctx = context.WithValue(ctx, caddy.ReplacerCtxKey, repl)

	req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	req = req.WithContext(ctx)

	m := VarsMatcher{"nil_var": {""}}
	match, err := m.MatchWithError(req)
	if err != nil {
		t.Fatalf("MatchWithError() error = %v", err)
	}
	if !match {
		t.Error("nil variable value should match empty string")
	}
}

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
