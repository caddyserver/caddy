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
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

func TestHostMatcher(t *testing.T) {
	err := os.Setenv("GO_BENCHMARK_DOMAIN", "localhost")
	if err != nil {
		t.Errorf("error while setting up environment: %v", err)
	}

	for i, tc := range []struct {
		match  MatchHost
		input  string
		expect bool
	}{
		{
			match:  MatchHost{},
			input:  "example.com",
			expect: false,
		},
		{
			match:  MatchHost{"example.com"},
			input:  "example.com",
			expect: true,
		},
		{
			match:  MatchHost{"EXAMPLE.COM"},
			input:  "example.com",
			expect: true,
		},
		{
			match:  MatchHost{"example.com"},
			input:  "EXAMPLE.COM",
			expect: true,
		},
		{
			match:  MatchHost{"example.com"},
			input:  "foo.example.com",
			expect: false,
		},
		{
			match:  MatchHost{"example.com"},
			input:  "EXAMPLE.COM",
			expect: true,
		},
		{
			match:  MatchHost{"foo.example.com"},
			input:  "foo.example.com",
			expect: true,
		},
		{
			match:  MatchHost{"foo.example.com"},
			input:  "bar.example.com",
			expect: false,
		},
		{
			match:  MatchHost{"éxàmplê.com"},
			input:  "xn--xmpl-0na6cm.com",
			expect: true,
		},
		{
			match:  MatchHost{"*.example.com"},
			input:  "example.com",
			expect: false,
		},
		{
			match:  MatchHost{"*.example.com"},
			input:  "SUB.EXAMPLE.COM",
			expect: true,
		},
		{
			match:  MatchHost{"*.example.com"},
			input:  "foo.example.com",
			expect: true,
		},
		{
			match:  MatchHost{"*.example.com"},
			input:  "foo.bar.example.com",
			expect: false,
		},
		{
			match:  MatchHost{"*.example.com", "example.net"},
			input:  "example.net",
			expect: true,
		},
		{
			match:  MatchHost{"example.net", "*.example.com"},
			input:  "foo.example.com",
			expect: true,
		},
		{
			match:  MatchHost{"*.example.net", "*.*.example.com"},
			input:  "foo.bar.example.com",
			expect: true,
		},
		{
			match:  MatchHost{"*.example.net", "sub.*.example.com"},
			input:  "sub.foo.example.com",
			expect: true,
		},
		{
			match:  MatchHost{"*.example.net", "sub.*.example.com"},
			input:  "sub.foo.example.net",
			expect: false,
		},
		{
			match:  MatchHost{"www.*.*"},
			input:  "www.example.com",
			expect: true,
		},
		{
			match:  MatchHost{"example.com"},
			input:  "example.com:5555",
			expect: true,
		},
		{
			match:  MatchHost{"{env.GO_BENCHMARK_DOMAIN}"},
			input:  "localhost",
			expect: true,
		},
		{
			match:  MatchHost{"{env.GO_NONEXISTENT}"},
			input:  "localhost",
			expect: false,
		},
	} {
		req := &http.Request{Host: tc.input}
		repl := caddy.NewReplacer()
		ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
		req = req.WithContext(ctx)

		if err := tc.match.Provision(caddy.Context{}); err != nil {
			t.Errorf("Test %d %v: provisioning failed: %v", i, tc.match, err)
		}

		actual, err := tc.match.MatchWithError(req)
		if err != nil {
			t.Errorf("Test %d %v: matching failed: %v", i, tc.match, err)
		}
		if actual != tc.expect {
			t.Errorf("Test %d %v: Expected %t, got %t for '%s'", i, tc.match, tc.expect, actual, tc.input)
			continue
		}
	}
}

func TestPathMatcher(t *testing.T) {
	for i, tc := range []struct {
		match        MatchPath // not URI-encoded because not parsing from a URI
		input        string    // should be valid URI encoding (escaped) since it will become part of a request
		expect       bool
		provisionErr bool
	}{
		{
			match:  MatchPath{},
			input:  "/",
			expect: false,
		},
		{
			match:  MatchPath{"/"},
			input:  "/",
			expect: true,
		},
		{
			match:  MatchPath{"/foo/bar"},
			input:  "/",
			expect: false,
		},
		{
			match:  MatchPath{"/foo/bar"},
			input:  "/foo/bar",
			expect: true,
		},
		{
			match:  MatchPath{"/foo/bar/"},
			input:  "/foo/bar",
			expect: false,
		},
		{
			match:  MatchPath{"/foo/bar/"},
			input:  "/foo/bar/",
			expect: true,
		},
		{
			match:  MatchPath{"/foo/bar/", "/other"},
			input:  "/other/",
			expect: false,
		},
		{
			match:  MatchPath{"/foo/bar/", "/other"},
			input:  "/other",
			expect: true,
		},
		{
			match:  MatchPath{"*.ext"},
			input:  "/foo/bar.ext",
			expect: true,
		},
		{
			match:  MatchPath{"*.php"},
			input:  "/index.PHP",
			expect: true,
		},
		{
			match:  MatchPath{"*.ext"},
			input:  "/foo/bar.ext",
			expect: true,
		},
		{
			match:  MatchPath{"/foo/*/baz"},
			input:  "/foo/bar/baz",
			expect: true,
		},
		{
			match:  MatchPath{"/foo/*/baz/bam"},
			input:  "/foo/bar/bam",
			expect: false,
		},
		{
			match:  MatchPath{"*substring*"},
			input:  "/foo/substring/bar.txt",
			expect: true,
		},
		{
			match:  MatchPath{"/foo"},
			input:  "/foo/bar",
			expect: false,
		},
		{
			match:  MatchPath{"/foo"},
			input:  "/foo/bar",
			expect: false,
		},
		{
			match:  MatchPath{"/foo"},
			input:  "/FOO",
			expect: true,
		},
		{
			match:  MatchPath{"/foo*"},
			input:  "/FOOOO",
			expect: true,
		},
		{
			match:  MatchPath{"/foo/bar.txt"},
			input:  "/foo/BAR.txt",
			expect: true,
		},
		{
			match:  MatchPath{"/foo*"},
			input:  "//foo/bar",
			expect: true,
		},
		{
			match:  MatchPath{"/foo"},
			input:  "//foo",
			expect: true,
		},
		{
			match:  MatchPath{"//foo"},
			input:  "/foo",
			expect: false,
		},
		{
			match:  MatchPath{"//foo"},
			input:  "//foo",
			expect: true,
		},
		{
			match:  MatchPath{"/foo//*"},
			input:  "/foo//bar",
			expect: true,
		},
		{
			match:  MatchPath{"/foo//*"},
			input:  "/foo/%2Fbar",
			expect: true,
		},
		{
			match:  MatchPath{"/foo/%2F*"},
			input:  "/foo/%2Fbar",
			expect: true,
		},
		{
			match:  MatchPath{"/foo/%2F*"},
			input:  "/foo//bar",
			expect: false,
		},
		{
			match:  MatchPath{"/foo//bar"},
			input:  "/foo//bar",
			expect: true,
		},
		{
			match:  MatchPath{"/foo/*//bar"},
			input:  "/foo///bar",
			expect: true,
		},
		{
			match:  MatchPath{"/foo/%*//bar"},
			input:  "/foo///bar",
			expect: true,
		},
		{
			match:  MatchPath{"/foo/%*//bar"},
			input:  "/foo//%2Fbar",
			expect: true,
		},
		{
			match:  MatchPath{"/foo*"},
			input:  "/%2F/foo",
			expect: true,
		},
		{
			match:  MatchPath{"*"},
			input:  "/",
			expect: true,
		},
		{
			match:  MatchPath{"*"},
			input:  "/foo/bar",
			expect: true,
		},
		{
			match:  MatchPath{"**"},
			input:  "/",
			expect: true,
		},
		{
			match:  MatchPath{"**"},
			input:  "/foo/bar",
			expect: true,
		},
		// notice these next three test cases are the same normalized path but are written differently
		{
			match:  MatchPath{"/%25@.txt"},
			input:  "/%25@.txt",
			expect: true,
		},
		{
			match:  MatchPath{"/%25@.txt"},
			input:  "/%25%40.txt",
			expect: true,
		},
		{
			match:  MatchPath{"/%25%40.txt"},
			input:  "/%25%40.txt",
			expect: true,
		},
		{
			match:  MatchPath{"/bands/*/*"},
			input:  "/bands/AC%2FDC/T.N.T",
			expect: false, // because * operates in normalized space
		},
		{
			match:  MatchPath{"/bands/%*/%*"},
			input:  "/bands/AC%2FDC/T.N.T",
			expect: true,
		},
		{
			match:  MatchPath{"/bands/%*/%*"},
			input:  "/bands/AC/DC/T.N.T",
			expect: false,
		},
		{
			match:  MatchPath{"/bands/%*"},
			input:  "/bands/AC/DC",
			expect: false, // not a suffix match
		},
		{
			match:  MatchPath{"/bands/%*"},
			input:  "/bands/AC%2FDC",
			expect: true,
		},
		{
			match:  MatchPath{"/foo%2fbar/baz"},
			input:  "/foo%2Fbar/baz",
			expect: true,
		},
		{
			match:  MatchPath{"/foo%2fbar/baz"},
			input:  "/foo/bar/baz",
			expect: false,
		},
		{
			match:  MatchPath{"/foo/bar/baz"},
			input:  "/foo%2fbar/baz",
			expect: true,
		},
		{
			match:  MatchPath{"/admin%2fpanel"},
			input:  "/ADMIN%2fpanel",
			expect: true,
		},
		{
			match:  MatchPath{"/admin%2fpa*el"},
			input:  "/ADMIN%2fPaAzZLm123NEL",
			expect: true,
		},
		{
			match:  MatchPath{"/foo%2fbar"},
			input:  "/foo%2fbarbaz",
			expect: false,
		},
		{
			match:  MatchPath{"/foo%2f"},
			input:  "/foo%2fx",
			expect: false,
		},
		{
			match:  MatchPath{"/admin%2fpanel"},
			input:  "/admin%2fpanelX",
			expect: false,
		},
	} {
		err := tc.match.Provision(caddy.Context{})
		if err == nil && tc.provisionErr {
			t.Errorf("Test %d %v: Expected error provisioning, but there was no error", i, tc.match)
		}
		if err != nil && !tc.provisionErr {
			t.Errorf("Test %d %v: Expected no error provisioning, but there was an error: %v", i, tc.match, err)
		}
		if tc.provisionErr {
			continue // if it's not supposed to provision properly, pointless to test it
		}

		u, err := url.ParseRequestURI(tc.input)
		if err != nil {
			t.Fatalf("Test %d (%v): Invalid request URI (should be rejected by Go's HTTP server): %v", i, tc.input, err)
		}
		req := &http.Request{URL: u}
		repl := caddy.NewReplacer()
		ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
		req = req.WithContext(ctx)

		actual, err := tc.match.MatchWithError(req)
		if err != nil {
			t.Errorf("Test %d %v: matching failed: %v", i, tc.match, err)
		}
		if actual != tc.expect {
			t.Errorf("Test %d %v: Expected %t, got %t for '%s'", i, tc.match, tc.expect, actual, tc.input)
			continue
		}
	}
}

// Path matching is case-insensitive, but placeholder names are case-sensitive.
func TestPathMatcherPlaceholders(t *testing.T) {
	for _, tc := range []struct {
		name         string
		pattern      string
		placeholders map[string]string
		input        string
		want         bool
	}{
		{
			name:         "uppercase value",
			pattern:      "/charts/DAPS-{http.vars.cycle}/",
			placeholders: map[string]string{"http.vars.cycle": "2024-MAR-21"},
			input:        "/charts/DAPS-2024-MAR-21/",
			want:         true,
		},
		{
			name:         "case-sensitive name",
			pattern:      "/{http.vars.Cycle}",
			placeholders: map[string]string{"http.vars.Cycle": "good", "http.vars.cycle": "wrong"},
			input:        "/good",
			want:         true,
		},
		{
			name:         "different placeholder",
			pattern:      "/{http.vars.Cycle}",
			placeholders: map[string]string{"http.vars.Cycle": "good", "http.vars.cycle": "wrong"},
			input:        "/wrong",
			want:         false,
		},
		{
			name:         "prefix",
			pattern:      "/API/{http.vars.Cycle}/*",
			placeholders: map[string]string{"http.vars.Cycle": "CURRENT"},
			input:        "/api/current/file.txt",
			want:         true,
		},
		{
			name:         "suffix",
			pattern:      "*{http.vars.extension}",
			placeholders: map[string]string{"http.vars.extension": ".TXT"},
			input:        "/file.txt",
			want:         true,
		},
		{
			name:         "substring",
			pattern:      "*{http.vars.part}*",
			placeholders: map[string]string{"http.vars.part": "MIDDLE"},
			input:        "/start-middle-end",
			want:         true,
		},
		{
			name:         "glob",
			pattern:      "/{http.vars.kind}/*/END",
			placeholders: map[string]string{"http.vars.kind": "DAPS"},
			input:        "/daps/file/end",
			want:         true,
		},
		{
			name:         "multiple placeholders",
			pattern:      "/{http.vars.Kind}/{http.vars.Cycle}/",
			placeholders: map[string]string{"http.vars.Kind": "DAPS", "http.vars.Cycle": "2024-MAR-21"},
			input:        "/daps/2024-mar-21/",
			want:         true,
		},
		{
			name:         "escaped slash",
			pattern:      "/{http.vars.path}",
			placeholders: map[string]string{"http.vars.path": "FOO%2FBAR"},
			input:        "/foo%2fbar",
			want:         true,
		},
		{
			name:         "escaped slash differs from separator",
			pattern:      "/{http.vars.path}",
			placeholders: map[string]string{"http.vars.path": "FOO%2FBAR"},
			input:        "/foo/bar",
			want:         false,
		},
		{
			name:         "unicode value",
			pattern:      "/{http.vars.name}",
			placeholders: map[string]string{"http.vars.name": "CAFÉ"},
			input:        "/caf%C3%A9",
			want:         true,
		},
		{
			name:    "missing placeholder",
			pattern: "/API/{http.vars.missing}Foo",
			input:   "/api/foo",
			want:    true,
		},
		{
			name:    "escaped closing brace prefix",
			pattern: `/API/\}*`,
			input:   "/api/%7Dfile",
			want:    true,
		},
		{
			name:         "escaped literal placeholder",
			pattern:      `/API/\{Cycle\}*`,
			placeholders: map[string]string{"Cycle": "WRONG"},
			input:        "/api/%7Bcycle%7Dfile",
			want:         true,
		},
		{
			name:    "unclosed placeholder",
			pattern: "/API/{Cycle*",
			input:   "/api/%7Bcycle-file",
			want:    true,
		},
		{
			name:         "clean request path after expansion",
			pattern:      "/{http.vars.Directory}/*",
			placeholders: map[string]string{"http.vars.Directory": "PRIVATE"},
			input:        "/public/../private//file",
			want:         true,
		},
		{
			name:         "preserve double slashes after expansion",
			pattern:      "/{http.vars.Directory}//FILE",
			placeholders: map[string]string{"http.vars.Directory": "PRIVATE"},
			input:        "/private//file",
			want:         true,
		},
		{
			name:         "double slashes differ from single separator",
			pattern:      "/{http.vars.Directory}//FILE",
			placeholders: map[string]string{"http.vars.Directory": "PRIVATE"},
			input:        "/private/file",
			want:         false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			matcher := MatchPath{tc.pattern}
			if err := matcher.Provision(caddy.Context{}); err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodGet, tc.input, nil)
			repl := caddy.NewReplacer()
			for key, value := range tc.placeholders {
				repl.Set(key, value)
			}
			req = req.WithContext(context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl))
			got, err := matcher.MatchWithError(req)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("pattern %q with placeholders %v: matching %q = %t, want %t", tc.pattern, tc.placeholders, tc.input, got, tc.want)
			}
		})
	}
}

func TestPathMatcherPlaceholderPerRequest(t *testing.T) {
	matcher := MatchPath{"/API/{http.vars.Cycle}/"}
	if err := matcher.Provision(caddy.Context{}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		value string
		input string
		want  bool
	}{
		{value: "FIRST", input: "/api/first/", want: true},
		{value: "SECOND", input: "/api/second/", want: true},
		{value: "SECOND", input: "/api/first/", want: false},
	} {
		repl := caddy.NewReplacer()
		repl.Set("http.vars.Cycle", tc.value)
		req := httptest.NewRequest(http.MethodGet, tc.input, nil)
		req = req.WithContext(context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl))
		matched, err := matcher.MatchWithError(req)
		if err != nil || matched != tc.want {
			t.Errorf("value %q: matching %q = %t, error = %v, want %t", tc.value, tc.input, matched, err, tc.want)
		}
		if value, _ := repl.Get("http.vars.Cycle"); value != tc.value {
			t.Errorf("matching changed placeholder value from %q to %v", tc.value, value)
		}
	}
}

func BenchmarkPathMatcherPlaceholders(b *testing.B) {
	for _, tc := range []struct {
		name    string
		pattern string
		input   string
	}{
		{name: "static", pattern: "/API/CURRENT/", input: "/api/current/"},
		{name: "static_prefix", pattern: "/API/*", input: "/api/current/file.txt"},
		{name: "dynamic", pattern: "/API/{cycle}/", input: "/api/current/"},
		{name: "dynamic_lowercase_literal", pattern: "/api/{cycle}/", input: "/api/current/"},
		{name: "dynamic_without_literal", pattern: "/{cycle}", input: "/current"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			matcher := MatchPath{tc.pattern}
			if err := matcher.Provision(caddy.Context{}); err != nil {
				b.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodGet, tc.input, nil)
			repl := caddy.NewReplacer()
			repl.Set("cycle", "current")
			req = req.WithContext(context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl))
			b.ReportAllocs()
			for b.Loop() {
				if matched, err := matcher.MatchWithError(req); err != nil || !matched {
					b.Fatalf("match = %t, error = %v", matched, err)
				}
			}
		})
	}
}

func TestPathMatcherWindows(t *testing.T) {
	// only Windows has this bug where it will ignore
	// trailing dots and spaces in a filename
	if runtime.GOOS != "windows" {
		return
	}

	repl := caddy.NewReplacer()

	for _, tc := range []struct {
		name          string
		path          string
		requestTarget string
		match         MatchPath
	}{
		{
			name:  "trailing dots and spaces",
			path:  "/index.php . . ..",
			match: MatchPath{"*.php"},
		},
		{
			name:          "encoded backslash path separator",
			requestTarget: `/private%5csecret.txt`,
			match:         MatchPath{"/private/*"},
		},
		{
			name:          "encoded backslash path separator with escaped wildcard",
			requestTarget: `/private%5csecret.txt`,
			match:         MatchPath{"/private/%*"},
		},
		{
			name:          "uppercase encoded backslash path separator with escaped wildcard",
			requestTarget: `/private%5Csecret.txt`,
			match:         MatchPath{"/private/%*"},
		},
		{
			name:          "encoded backslash in escaped pattern",
			requestTarget: `/private%5csecret.txt`,
			match:         MatchPath{"/private%5c%*"},
		},
		{
			name:  "trailing dot on a middle path component",
			path:  "/private./secret.txt",
			match: MatchPath{"/private/*"},
		},
		{
			name:  "trailing space on a middle path component",
			path:  "/private /secret.txt",
			match: MatchPath{"/private/*"},
		},
		{
			// escaped-space matcher (pattern contains '%'): the trailing
			// dot/space normalization must also apply on the escaped-path
			// branch, otherwise /private.%5csecret.txt bypasses /private%2f*.
			name:          "trailing dot before encoded backslash, escaped-space matcher",
			requestTarget: `/private.%5csecret.txt`,
			match:         MatchPath{"/private%2f*"},
		},
		{
			name:          "encoded trailing dot before encoded backslash, escaped-space matcher",
			requestTarget: `/private%2e%5csecret.txt`,
			match:         MatchPath{"/private%2f*"},
		},
		{
			name:          "encoded trailing space before encoded backslash, escaped-space matcher",
			requestTarget: `/private%20%5csecret.txt`,
			match:         MatchPath{"/private%2f*"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := &url.URL{Path: tc.path}
			if tc.requestTarget != "" {
				var err error
				u, err = url.ParseRequestURI(tc.requestTarget)
				if err != nil {
					t.Fatalf("Parsing request target: %v", err)
				}
			}
			req := &http.Request{URL: u}
			ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
			req = req.WithContext(ctx)

			matched, err := tc.match.MatchWithError(req)
			if err != nil {
				t.Errorf("Expected no error, but got: %v", err)
			}
			if !matched {
				t.Errorf("Expected %q to match %v", req.URL.Path, tc.match)
			}
		})
	}
}

func TestPathREMatcherWindows(t *testing.T) {
	// Windows treats backslashes as path separators and ignores trailing
	// dots and spaces per path component, so the path_regexp matcher must
	// normalize them the same way the path matcher does (see #5613);
	// otherwise a guard such as `path_regexp ^/private/` is bypassed by e.g.
	// GET /private\secret.txt (or %5c) or GET /private./secret.txt.
	if runtime.GOOS != "windows" {
		return
	}

	repl := caddy.NewReplacer()

	for _, tc := range []struct {
		name          string
		path          string
		requestTarget string
		match         MatchPathRE
	}{
		{
			name:  "literal backslash path separator",
			path:  `/private\secret.txt`,
			match: MatchPathRE{MatchRegexp{Pattern: "^/private/"}},
		},
		{
			name:          "encoded backslash path separator",
			requestTarget: `/private%5csecret.txt`,
			match:         MatchPathRE{MatchRegexp{Pattern: "^/private/"}},
		},
		{
			name:          "uppercase encoded backslash path separator",
			requestTarget: `/private%5Csecret.txt`,
			match:         MatchPathRE{MatchRegexp{Pattern: "^/private/"}},
		},
		{
			name:  "trailing dot on a middle path component",
			path:  `/private./secret.txt`,
			match: MatchPathRE{MatchRegexp{Pattern: "^/private/"}},
		},
		{
			name:  "trailing space on a middle path component",
			path:  `/private /secret.txt`,
			match: MatchPathRE{MatchRegexp{Pattern: "^/private/"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.match.Provision(caddy.Context{}); err != nil {
				t.Fatalf("Provisioning: %v", err)
			}

			u := &url.URL{Path: tc.path}
			if tc.requestTarget != "" {
				var err error
				u, err = url.ParseRequestURI(tc.requestTarget)
				if err != nil {
					t.Fatalf("Parsing request target: %v", err)
				}
			}
			req := &http.Request{URL: u}
			ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
			req = req.WithContext(ctx)

			matched, err := tc.match.MatchWithError(req)
			if err != nil {
				t.Errorf("Expected no error, but got: %v", err)
			}
			if !matched {
				t.Errorf("Expected %q to match %v", req.URL.Path, tc.match.Pattern)
			}
		})
	}
}

func TestPathREMatcher(t *testing.T) {
	for i, tc := range []struct {
		match      MatchPathRE
		input      string
		expect     bool
		expectRepl map[string]string
	}{
		{
			match:  MatchPathRE{},
			input:  "/",
			expect: true,
		},
		{
			match:  MatchPathRE{MatchRegexp{Pattern: "/"}},
			input:  "/",
			expect: true,
		},
		{
			match:  MatchPathRE{MatchRegexp{Pattern: "^/foo"}},
			input:  "/foo",
			expect: true,
		},
		{
			match:  MatchPathRE{MatchRegexp{Pattern: "^/foo"}},
			input:  "/foo/",
			expect: true,
		},
		{
			match:  MatchPathRE{MatchRegexp{Pattern: "^/foo"}},
			input:  "//foo",
			expect: true,
		},
		{
			match:  MatchPathRE{MatchRegexp{Pattern: "^/foo"}},
			input:  "//foo/",
			expect: true,
		},
		{
			match:  MatchPathRE{MatchRegexp{Pattern: "^/foo"}},
			input:  "/%2F/foo/",
			expect: true,
		},
		{
			match:  MatchPathRE{MatchRegexp{Pattern: "/bar"}},
			input:  "/foo/",
			expect: false,
		},
		{
			match:  MatchPathRE{MatchRegexp{Pattern: "^/bar"}},
			input:  "/foo/bar",
			expect: false,
		},
		{
			match:      MatchPathRE{MatchRegexp{Pattern: "^/foo/(.*)/baz$", Name: "name"}},
			input:      "/foo/bar/baz",
			expect:     true,
			expectRepl: map[string]string{"name.1": "bar"},
		},
		{
			match:      MatchPathRE{MatchRegexp{Pattern: "^/foo/(?P<myparam>.*)/baz$", Name: "name"}},
			input:      "/foo/bar/baz",
			expect:     true,
			expectRepl: map[string]string{"name.myparam": "bar"},
		},
		{
			match:  MatchPathRE{MatchRegexp{Pattern: "^/%@.txt"}},
			input:  "/%25@.txt",
			expect: true,
		},
		{
			match:  MatchPathRE{MatchRegexp{Pattern: "^/%25@.txt"}},
			input:  "/%25@.txt",
			expect: false,
		},
	} {
		// compile the regexp and validate its name
		err := tc.match.Provision(caddy.Context{})
		if err != nil {
			t.Errorf("Test %d %v: Provisioning: %v", i, tc.match, err)
			continue
		}
		err = tc.match.Validate()
		if err != nil {
			t.Errorf("Test %d %v: Validating: %v", i, tc.match, err)
			continue
		}

		// set up the fake request and its Replacer
		u, err := url.ParseRequestURI(tc.input)
		if err != nil {
			t.Fatalf("Test %d: Bad input URI: %v", i, err)
		}
		req := &http.Request{URL: u}
		repl := caddy.NewReplacer()
		ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
		req = req.WithContext(ctx)
		addHTTPVarsToReplacer(repl, req, httptest.NewRecorder())

		actual, err := tc.match.MatchWithError(req)
		if err != nil {
			t.Errorf("Test %d %v: matching failed: %v", i, tc.match, err)
		}
		if actual != tc.expect {
			t.Errorf("Test %d [%v]: Expected %t, got %t for input '%s'",
				i, tc.match.Pattern, tc.expect, actual, tc.input)
			continue
		}

		for key, expectVal := range tc.expectRepl {
			placeholder := fmt.Sprintf("{http.regexp.%s}", key)
			actualVal := repl.ReplaceAll(placeholder, "<empty>")
			if actualVal != expectVal {
				t.Errorf("Test %d [%v]: Expected placeholder {http.regexp.%s} to be '%s' but got '%s'",
					i, tc.match.Pattern, key, expectVal, actualVal)
				continue
			}
		}
	}
}

func TestHeaderMatcher(t *testing.T) {
	repl := caddy.NewReplacer()
	repl.Set("a", "foobar")

	for i, tc := range []struct {
		match  MatchHeader
		input  http.Header // make sure these are canonical cased (std lib will do that in a real request)
		host   string
		expect bool
	}{
		{
			match:  MatchHeader{"Field": []string{"foo"}},
			input:  http.Header{"Field": []string{"foo"}},
			expect: true,
		},
		{
			match:  MatchHeader{"Field": []string{"foo", "bar"}},
			input:  http.Header{"Field": []string{"bar"}},
			expect: true,
		},
		{
			match:  MatchHeader{"Field": []string{"foo", "bar"}},
			input:  http.Header{"Alakazam": []string{"kapow"}},
			expect: false,
		},
		{
			match:  MatchHeader{"Field": []string{"foo", "bar"}},
			input:  http.Header{"Field": []string{"kapow"}},
			expect: false,
		},
		{
			match:  MatchHeader{"Field": []string{"foo", "bar"}},
			input:  http.Header{"Field": []string{"kapow", "foo"}},
			expect: true,
		},
		{
			match:  MatchHeader{"Field1": []string{"foo"}, "Field2": []string{"bar"}},
			input:  http.Header{"Field1": []string{"foo"}, "Field2": []string{"bar"}},
			expect: true,
		},
		{
			match:  MatchHeader{"field1": []string{"foo"}, "field2": []string{"bar"}},
			input:  http.Header{"Field1": []string{"foo"}, "Field2": []string{"bar"}},
			expect: true,
		},
		{
			match:  MatchHeader{"field1": []string{"foo"}, "field2": []string{"bar"}},
			input:  http.Header{"Field1": []string{"foo"}, "Field2": []string{"kapow"}},
			expect: false,
		},
		{
			match:  MatchHeader{"field1": []string{"*"}},
			input:  http.Header{"Field1": []string{"foo"}},
			expect: true,
		},
		{
			match:  MatchHeader{"field1": []string{"*"}},
			input:  http.Header{"Field2": []string{"foo"}},
			expect: false,
		},
		{
			match:  MatchHeader{"Field1": []string{"foo*"}},
			input:  http.Header{"Field1": []string{"foo"}},
			expect: true,
		},
		{
			match:  MatchHeader{"Field1": []string{"foo*"}},
			input:  http.Header{"Field1": []string{"asdf", "foobar"}},
			expect: true,
		},
		{
			match:  MatchHeader{"Field1": []string{"*bar"}},
			input:  http.Header{"Field1": []string{"asdf", "foobar"}},
			expect: true,
		},
		{
			match:  MatchHeader{"host": []string{"localhost"}},
			input:  http.Header{},
			host:   "localhost",
			expect: true,
		},
		{
			match:  MatchHeader{"host": []string{"localhost"}},
			input:  http.Header{},
			host:   "caddyserver.com",
			expect: false,
		},
		{
			match:  MatchHeader{"Must-Not-Exist": nil},
			input:  http.Header{},
			expect: true,
		},
		{
			match:  MatchHeader{"Must-Not-Exist": nil},
			input:  http.Header{"Must-Not-Exist": []string{"do not match"}},
			expect: false,
		},
		{
			match:  MatchHeader{"Foo": []string{"{a}"}},
			input:  http.Header{"Foo": []string{"foobar"}},
			expect: true,
		},
		{
			match:  MatchHeader{"Foo": []string{"{a}"}},
			input:  http.Header{"Foo": []string{"asdf"}},
			expect: false,
		},
		{
			match:  MatchHeader{"Foo": []string{"{a}*"}},
			input:  http.Header{"Foo": []string{"foobar-baz"}},
			expect: true,
		},
	} {
		req := &http.Request{Header: tc.input, Host: tc.host}
		ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
		req = req.WithContext(ctx)

		actual, err := tc.match.MatchWithError(req)
		if err != nil {
			t.Errorf("Test %d %v: matching failed: %v", i, tc.match, err)
		}
		if actual != tc.expect {
			t.Errorf("Test %d %v: Expected %t, got %t for '%s'", i, tc.match, tc.expect, actual, tc.input)
			continue
		}
	}
}

func TestQueryMatcher(t *testing.T) {
	for i, tc := range []struct {
		scenario string
		match    MatchQuery
		input    string
		expect   bool
	}{
		{
			scenario: "non match against a specific value",
			match:    MatchQuery{"debug": []string{"1"}},
			input:    "/",
			expect:   false,
		},
		{
			scenario: "match against a specific value",
			match:    MatchQuery{"debug": []string{"1"}},
			input:    "/?debug=1",
			expect:   true,
		},
		{
			scenario: "match against a wildcard",
			match:    MatchQuery{"debug": []string{"*"}},
			input:    "/?debug=something",
			expect:   true,
		},
		{
			scenario: "non match against a wildcarded",
			match:    MatchQuery{"debug": []string{"*"}},
			input:    "/?other=something",
			expect:   false,
		},
		{
			scenario: "match against an empty value",
			match:    MatchQuery{"debug": []string{""}},
			input:    "/?debug",
			expect:   true,
		},
		{
			scenario: "non match against an empty value",
			match:    MatchQuery{"debug": []string{""}},
			input:    "/?someparam",
			expect:   false,
		},
		{
			scenario: "empty matcher value should match empty query",
			match:    MatchQuery{},
			input:    "/?",
			expect:   true,
		},
		{
			scenario: "nil matcher value should NOT match a non-empty query",
			match:    MatchQuery{},
			input:    "/?foo=bar",
			expect:   false,
		},
		{
			scenario: "non-nil matcher should NOT match an empty query",
			match:    MatchQuery{"": nil},
			input:    "/?",
			expect:   false,
		},
		{
			scenario: "match against a placeholder value",
			match:    MatchQuery{"debug": []string{"{http.vars.debug}"}},
			input:    "/?debug=1",
			expect:   true,
		},
		{
			scenario: "match against a placeholder key",
			match:    MatchQuery{"{http.vars.key}": []string{"1"}},
			input:    "/?somekey=1",
			expect:   true,
		},
		{
			scenario: "do not match when not all query params are present",
			match:    MatchQuery{"debug": []string{"1"}, "foo": []string{"bar"}},
			input:    "/?debug=1",
			expect:   false,
		},
		{
			scenario: "match when all query params are present",
			match:    MatchQuery{"debug": []string{"1"}, "foo": []string{"bar"}},
			input:    "/?debug=1&foo=bar",
			expect:   true,
		},
		{
			scenario: "do not match when the value of a query param does not match",
			match:    MatchQuery{"debug": []string{"1"}, "foo": []string{"bar"}},
			input:    "/?debug=2&foo=bar",
			expect:   false,
		},
		{
			scenario: "do not match when all the values the query params do not match",
			match:    MatchQuery{"debug": []string{"1"}, "foo": []string{"bar"}},
			input:    "/?debug=2&foo=baz",
			expect:   false,
		},
		{
			scenario: "match against two values for the same key",
			match:    MatchQuery{"debug": []string{"1"}},
			input:    "/?debug=1&debug=2",
			expect:   true,
		},
		{
			scenario: "match against two values for the same key",
			match:    MatchQuery{"debug": []string{"2", "1"}},
			input:    "/?debug=2&debug=1",
			expect:   true,
		},
	} {

		u, _ := url.Parse(tc.input)

		req := &http.Request{URL: u}
		repl := caddy.NewReplacer()
		ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
		repl.Set("http.vars.debug", "1")
		repl.Set("http.vars.key", "somekey")
		req = req.WithContext(ctx)
		actual, err := tc.match.MatchWithError(req)
		if err != nil {
			t.Errorf("Test %d %v: matching failed: %v", i, tc.match, err)
		}
		if actual != tc.expect {
			t.Errorf("Test %d %v: Expected %t, got %t for '%s'", i, tc.match, tc.expect, actual, tc.input)
			continue
		}
	}
}

func TestHeaderREMatcher(t *testing.T) {
	for i, tc := range []struct {
		match      MatchHeaderRE
		input      http.Header // make sure these are canonical cased (std lib will do that in a real request)
		host       string
		expect     bool
		expectRepl map[string]string
	}{
		{
			match:  MatchHeaderRE{"Field": &MatchRegexp{Pattern: "foo"}},
			input:  http.Header{"Field": []string{"foo"}},
			expect: true,
		},
		{
			match:  MatchHeaderRE{"Field": &MatchRegexp{Pattern: "$foo^"}},
			input:  http.Header{"Field": []string{"foobar"}},
			expect: false,
		},
		{
			match:      MatchHeaderRE{"Field": &MatchRegexp{Pattern: "^foo(.*)$", Name: "name"}},
			input:      http.Header{"Field": []string{"foobar"}},
			expect:     true,
			expectRepl: map[string]string{"name.1": "bar"},
		},
		{
			match:  MatchHeaderRE{"Field": &MatchRegexp{Pattern: "^foo.*$", Name: "name"}},
			input:  http.Header{"Field": []string{"barfoo", "foobar"}},
			expect: true,
		},
		{
			match:  MatchHeaderRE{"host": &MatchRegexp{Pattern: "^localhost$", Name: "name"}},
			input:  http.Header{},
			host:   "localhost",
			expect: true,
		},
		{
			match:  MatchHeaderRE{"host": &MatchRegexp{Pattern: "^local$", Name: "name"}},
			input:  http.Header{},
			host:   "localhost",
			expect: false,
		},
	} {
		// compile the regexp and validate its name
		err := tc.match.Provision(caddy.Context{})
		if err != nil {
			t.Errorf("Test %d %v: Provisioning: %v", i, tc.match, err)
			continue
		}
		err = tc.match.Validate()
		if err != nil {
			t.Errorf("Test %d %v: Validating: %v", i, tc.match, err)
			continue
		}

		// set up the fake request and its Replacer
		req := &http.Request{Header: tc.input, URL: new(url.URL), Host: tc.host}
		repl := caddy.NewReplacer()
		ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
		req = req.WithContext(ctx)
		addHTTPVarsToReplacer(repl, req, httptest.NewRecorder())

		actual, err := tc.match.MatchWithError(req)
		if err != nil {
			t.Errorf("Test %d %v: matching failed: %v", i, tc.match, err)
		}
		if actual != tc.expect {
			t.Errorf("Test %d [%v]: Expected %t, got %t for input '%s'",
				i, tc.match, tc.expect, actual, tc.input)
			continue
		}

		for key, expectVal := range tc.expectRepl {
			placeholder := fmt.Sprintf("{http.regexp.%s}", key)
			actualVal := repl.ReplaceAll(placeholder, "<empty>")
			if actualVal != expectVal {
				t.Errorf("Test %d [%v]: Expected placeholder {http.regexp.%s} to be '%s' but got '%s'",
					i, tc.match, key, expectVal, actualVal)
				continue
			}
		}
	}
}

func BenchmarkHeaderREMatcher(b *testing.B) {
	i := 0
	match := MatchHeaderRE{"Field": &MatchRegexp{Pattern: "^foo(.*)$", Name: "name"}}
	input := http.Header{"Field": []string{"foobar"}}
	var host string
	err := match.Provision(caddy.Context{})
	if err != nil {
		b.Errorf("Test %d %v: Provisioning: %v", i, match, err)
	}
	err = match.Validate()
	if err != nil {
		b.Errorf("Test %d %v: Validating: %v", i, match, err)
	}

	// set up the fake request and its Replacer
	req := &http.Request{Header: input, URL: new(url.URL), Host: host}
	repl := caddy.NewReplacer()
	ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
	req = req.WithContext(ctx)
	addHTTPVarsToReplacer(repl, req, httptest.NewRecorder())
	for b.Loop() {
		match.MatchWithError(req)
	}
}

func TestVarREMatcher(t *testing.T) {
	for i, tc := range []struct {
		desc       string
		match      MatchVarsRE
		input      VarsMiddleware
		headers    http.Header
		expect     bool
		expectRepl map[string]string
	}{
		{
			desc:   "match static value within var set by the VarsMiddleware succeeds",
			match:  MatchVarsRE{"Var1": &MatchRegexp{Pattern: "foo"}},
			input:  VarsMiddleware{"Var1": "here is foo val"},
			expect: true,
		},
		{
			desc:   "value set by VarsMiddleware not satisfying regexp matcher fails to match",
			match:  MatchVarsRE{"Var1": &MatchRegexp{Pattern: "$foo^"}},
			input:  VarsMiddleware{"Var1": "foobar"},
			expect: false,
		},
		{
			desc:       "successfully matched value is captured and its placeholder is added to replacer",
			match:      MatchVarsRE{"Var1": &MatchRegexp{Pattern: "^foo(.*)$", Name: "name"}},
			input:      VarsMiddleware{"Var1": "foobar"},
			expect:     true,
			expectRepl: map[string]string{"name.1": "bar"},
		},
		{
			desc:   "matching against a value of standard variables succeeds",
			match:  MatchVarsRE{"{http.request.method}": &MatchRegexp{Pattern: "^G.[tT]$"}},
			input:  VarsMiddleware{},
			expect: true,
		},
		{
			desc:   "matching against value of var set by the VarsMiddleware and referenced by its placeholder succeeds",
			match:  MatchVarsRE{"{http.vars.Var1}": &MatchRegexp{Pattern: "[vV]ar[0-9]"}},
			input:  VarsMiddleware{"Var1": "var1Value"},
			expect: true,
		},
		{
			desc:       "placeholder key value containing braces is not double-expanded",
			match:      MatchVarsRE{"{http.request.header.X-Input}": &MatchRegexp{Pattern: ".+", Name: "val"}},
			input:      VarsMiddleware{},
			headers:    http.Header{"X-Input": []string{"{env.HOME}"}},
			expect:     true,
			expectRepl: map[string]string{"val.0": "{env.HOME}"},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()
			// compile the regexp and validate its name
			err := tc.match.Provision(caddy.Context{})
			if err != nil {
				t.Errorf("Test %d %v: Provisioning: %v", i, tc.match, err)
				return
			}
			err = tc.match.Validate()
			if err != nil {
				t.Errorf("Test %d %v: Validating: %v", i, tc.match, err)
				return
			}

			// set up the fake request and its Replacer
			req := &http.Request{URL: new(url.URL), Method: http.MethodGet, Header: tc.headers}
			repl := caddy.NewReplacer()
			ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
			ctx = context.WithValue(ctx, VarsCtxKey, make(map[string]any))
			req = req.WithContext(ctx)

			addHTTPVarsToReplacer(repl, req, httptest.NewRecorder())

			tc.input.ServeHTTP(httptest.NewRecorder(), req, emptyHandler)

			actual, err := tc.match.MatchWithError(req)
			if err != nil {
				t.Errorf("Test %d %v: matching failed: %v", i, tc.match, err)
			}
			if actual != tc.expect {
				t.Errorf("Test %d [%v]: Expected %t, got %t for input '%s'",
					i, tc.match, tc.expect, actual, tc.input)
				return
			}

			for key, expectVal := range tc.expectRepl {
				placeholder := fmt.Sprintf("{http.regexp.%s}", key)
				actualVal := repl.ReplaceAll(placeholder, "<empty>")
				if actualVal != expectVal {
					t.Errorf("Test %d [%v]: Expected placeholder {http.regexp.%s} to be '%s' but got '%s'",
						i, tc.match, key, expectVal, actualVal)
					return
				}
			}
		})
	}
}

func TestNotMatcher(t *testing.T) {
	for i, tc := range []struct {
		host, path string
		match      MatchNot
		expect     bool
	}{
		{
			host: "example.com", path: "/",
			match:  MatchNot{},
			expect: true,
		},
		{
			host: "example.com", path: "/foo",
			match: MatchNot{
				MatcherSets: []MatcherSet{
					{
						MatchPath{"/foo"},
					},
				},
			},
			expect: false,
		},
		{
			host: "example.com", path: "/bar",
			match: MatchNot{
				MatcherSets: []MatcherSet{
					{
						MatchPath{"/foo"},
					},
				},
			},
			expect: true,
		},
		{
			host: "example.com", path: "/bar",
			match: MatchNot{
				MatcherSets: []MatcherSet{
					{
						MatchPath{"/foo"},
					},
					{
						MatchHost{"example.com"},
					},
				},
			},
			expect: false,
		},
		{
			host: "example.com", path: "/bar",
			match: MatchNot{
				MatcherSets: []MatcherSet{
					{
						MatchPath{"/bar"},
					},
					{
						MatchHost{"example.com"},
					},
				},
			},
			expect: false,
		},
		{
			host: "example.com", path: "/foo",
			match: MatchNot{
				MatcherSets: []MatcherSet{
					{
						MatchPath{"/bar"},
					},
					{
						MatchHost{"sub.example.com"},
					},
				},
			},
			expect: true,
		},
		{
			host: "example.com", path: "/foo",
			match: MatchNot{
				MatcherSets: []MatcherSet{
					{
						MatchPath{"/foo"},
						MatchHost{"example.com"},
					},
				},
			},
			expect: false,
		},
		{
			host: "example.com", path: "/foo",
			match: MatchNot{
				MatcherSets: []MatcherSet{
					{
						MatchPath{"/bar"},
						MatchHost{"example.com"},
					},
				},
			},
			expect: true,
		},
	} {
		req := &http.Request{Host: tc.host, URL: &url.URL{Path: tc.path}}
		repl := caddy.NewReplacer()
		ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
		req = req.WithContext(ctx)

		actual, err := tc.match.MatchWithError(req)
		if err != nil {
			t.Errorf("Test %d %v: matching failed: %v", i, tc.match, err)
		}
		if actual != tc.expect {
			t.Errorf("Test %d %+v: Expected %t, got %t for: host=%s path=%s'", i, tc.match, tc.expect, actual, tc.host, tc.path)
			continue
		}
	}
}

func TestMethodMatcher(t *testing.T) {
	for i, tc := range []struct {
		scenario string
		match    MatchMethod
		input    string
		expect   bool
	}{
		{
			scenario: "match uppercase GET",
			match:    MatchMethod{"GET"},
			input:    http.MethodGet,
			expect:   true,
		},
		{
			scenario: "match lowercase get after Provision uppercases it",
			match:    MatchMethod{"get"},
			input:    http.MethodGet,
			expect:   true,
		},
		{
			scenario: "match mixed case Post after Provision uppercases it",
			match:    MatchMethod{"Post"},
			input:    http.MethodPost,
			expect:   true,
		},
		{
			scenario: "no match for wrong method",
			match:    MatchMethod{"GET"},
			input:    http.MethodPost,
			expect:   false,
		},
		{
			scenario: "match one of multiple methods",
			match:    MatchMethod{"get", "post"},
			input:    http.MethodPost,
			expect:   true,
		},
	} {
		req := &http.Request{Method: tc.input}
		if err := tc.match.Provision(caddy.Context{}); err != nil {
			t.Errorf("Test %d %v: provisioning failed: %v", i, tc.scenario, err)
		}
		actual, err := tc.match.MatchWithError(req)
		if err != nil {
			t.Errorf("Test %d %v: matching failed: %v", i, tc.scenario, err)
		}
		if actual != tc.expect {
			t.Errorf("Test %d %v: Expected %t, got %t for method=%s", i, tc.scenario, tc.expect, actual, tc.input)
			continue
		}
	}
}

func BenchmarkLargeHostMatcher(b *testing.B) {
	// this benchmark simulates a large host matcher (thousands of entries) where each
	// value is an exact hostname (not a placeholder or wildcard) - compare the results
	// of this with and without the binary search (comment out the various fast path
	// sections in Match) to conduct experiments

	const n = 10000
	lastHost := fmt.Sprintf("%d.example.com", n-1)
	req := &http.Request{Host: lastHost}
	repl := caddy.NewReplacer()
	ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
	req = req.WithContext(ctx)

	matcher := make(MatchHost, n)
	for i := 0; i < n; i++ {
		matcher[i] = fmt.Sprintf("%d.example.com", i)
	}
	err := matcher.Provision(caddy.Context{})
	if err != nil {
		b.Fatal(err)
	}

	for b.Loop() {
		matcher.MatchWithError(req)
	}
}

func BenchmarkHostMatcherWithoutPlaceholder(b *testing.B) {
	req := &http.Request{Host: "localhost"}
	repl := caddy.NewReplacer()
	ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
	req = req.WithContext(ctx)

	match := MatchHost{"localhost"}

	for b.Loop() {
		match.MatchWithError(req)
	}
}

func BenchmarkHostMatcherWithPlaceholder(b *testing.B) {
	err := os.Setenv("GO_BENCHMARK_DOMAIN", "localhost")
	if err != nil {
		b.Errorf("error while setting up environment: %v", err)
	}

	req := &http.Request{Host: "localhost"}
	repl := caddy.NewReplacer()
	ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
	req = req.WithContext(ctx)
	match := MatchHost{"{env.GO_BENCHMARK_DOMAIN}"}

	for b.Loop() {
		match.MatchWithError(req)
	}
}
