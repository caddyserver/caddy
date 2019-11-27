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

		actual := tc.match.Match(req)
		if actual != tc.expect {
			t.Errorf("Test %d %v: Expected %t, got %t for '%s'", i, tc.match, tc.expect, actual, tc.input)
			continue
		}
	}
}

func TestPathMatcher(t *testing.T) {
	for i, tc := range []struct {
		match  MatchPath
		input  string
		expect bool
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
			match:  MatchPath{"/foo/bar/", "/other"},
			input:  "/other/",
			expect: true,
		},
		{
			match:  MatchPath{"*.ext"},
			input:  "/foo.ext",
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
			match:  MatchPath{"/foo"},
			input:  "/FOO",
			expect: true,
		},
		{
			match:  MatchPath{"/foo/bar.txt"},
			input:  "/foo/BAR.txt",
			expect: true,
		},
	} {
		req := &http.Request{URL: &url.URL{Path: tc.input}}
		actual := tc.match.Match(req)
		if actual != tc.expect {
			t.Errorf("Test %d %v: Expected %t, got %t for '%s'", i, tc.match, tc.expect, actual, tc.input)
			continue
		}
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
			match:  MatchPathRE{MatchRegexp{Pattern: "/foo"}},
			input:  "/foo",
			expect: true,
		},
		{
			match:  MatchPathRE{MatchRegexp{Pattern: "/foo"}},
			input:  "/foo/",
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
		req := &http.Request{URL: &url.URL{Path: tc.input}}
		repl := caddy.NewReplacer()
		ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
		req = req.WithContext(ctx)
		addHTTPVarsToReplacer(repl, req, httptest.NewRecorder())

		actual := tc.match.Match(req)
		if actual != tc.expect {
			t.Errorf("Test %d [%v]: Expected %t, got %t for input '%s'",
				i, tc.match.Pattern, tc.expect, actual, tc.input)
			continue
		}

		for key, expectVal := range tc.expectRepl {
			placeholder := fmt.Sprintf("{http.matchers.path_regexp.%s}", key)
			actualVal := repl.ReplaceAll(placeholder, "<empty>")
			if actualVal != expectVal {
				t.Errorf("Test %d [%v]: Expected placeholder {http.matchers.path_regexp.%s} to be '%s' but got '%s'",
					i, tc.match.Pattern, key, expectVal, actualVal)
				continue
			}
		}
	}
}

func TestHeaderMatcher(t *testing.T) {
	for i, tc := range []struct {
		match  MatchHeader
		input  http.Header // make sure these are canonical cased (std lib will do that in a real request)
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
	} {
		req := &http.Request{Header: tc.input}
		actual := tc.match.Match(req)
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
	} {

		u, _ := url.Parse(tc.input)

		req := &http.Request{URL: u}
		actual := tc.match.Match(req)
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
		req := &http.Request{Header: tc.input, URL: new(url.URL)}
		repl := caddy.NewReplacer()
		ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
		req = req.WithContext(ctx)
		addHTTPVarsToReplacer(repl, req, httptest.NewRecorder())

		actual := tc.match.Match(req)
		if actual != tc.expect {
			t.Errorf("Test %d [%v]: Expected %t, got %t for input '%s'",
				i, tc.match, tc.expect, actual, tc.input)
			continue
		}

		for key, expectVal := range tc.expectRepl {
			placeholder := fmt.Sprintf("{http.matchers.header_regexp.%s}", key)
			actualVal := repl.ReplaceAll(placeholder, "<empty>")
			if actualVal != expectVal {
				t.Errorf("Test %d [%v]: Expected placeholder {http.matchers.header_regexp.%s} to be '%s' but got '%s'",
					i, tc.match, key, expectVal, actualVal)
				continue
			}
		}
	}
}

func TestResponseMatcher(t *testing.T) {
	for i, tc := range []struct {
		require ResponseMatcher
		status  int
		hdr     http.Header // make sure these are canonical cased (std lib will do that in a real request)
		expect  bool
	}{
		{
			require: ResponseMatcher{},
			status:  200,
			expect:  true,
		},
		{
			require: ResponseMatcher{
				StatusCode: []int{200},
			},
			status: 200,
			expect: true,
		},
		{
			require: ResponseMatcher{
				StatusCode: []int{2},
			},
			status: 200,
			expect: true,
		},
		{
			require: ResponseMatcher{
				StatusCode: []int{201},
			},
			status: 200,
			expect: false,
		},
		{
			require: ResponseMatcher{
				StatusCode: []int{2},
			},
			status: 301,
			expect: false,
		},
		{
			require: ResponseMatcher{
				StatusCode: []int{3},
			},
			status: 301,
			expect: true,
		},
		{
			require: ResponseMatcher{
				StatusCode: []int{3},
			},
			status: 399,
			expect: true,
		},
		{
			require: ResponseMatcher{
				StatusCode: []int{3},
			},
			status: 400,
			expect: false,
		},
		{
			require: ResponseMatcher{
				StatusCode: []int{3, 4},
			},
			status: 400,
			expect: true,
		},
		{
			require: ResponseMatcher{
				StatusCode: []int{3, 401},
			},
			status: 401,
			expect: true,
		},
		{
			require: ResponseMatcher{
				Headers: http.Header{
					"Foo": []string{"bar"},
				},
			},
			hdr:    http.Header{"Foo": []string{"bar"}},
			expect: true,
		},
		{
			require: ResponseMatcher{
				Headers: http.Header{
					"Foo2": []string{"bar"},
				},
			},
			hdr:    http.Header{"Foo": []string{"bar"}},
			expect: false,
		},
		{
			require: ResponseMatcher{
				Headers: http.Header{
					"Foo": []string{"bar", "baz"},
				},
			},
			hdr:    http.Header{"Foo": []string{"baz"}},
			expect: true,
		},
		{
			require: ResponseMatcher{
				Headers: http.Header{
					"Foo":  []string{"bar"},
					"Foo2": []string{"baz"},
				},
			},
			hdr:    http.Header{"Foo": []string{"baz"}},
			expect: false,
		},
		{
			require: ResponseMatcher{
				Headers: http.Header{
					"Foo":  []string{"bar"},
					"Foo2": []string{"baz"},
				},
			},
			hdr:    http.Header{"Foo": []string{"bar"}, "Foo2": []string{"baz"}},
			expect: true,
		},
	} {
		actual := tc.require.Match(tc.status, tc.hdr)
		if actual != tc.expect {
			t.Errorf("Test %d %v: Expected %t, got %t for HTTP %d %v", i, tc.require, tc.expect, actual, tc.status, tc.hdr)
			continue
		}
	}
}

func BenchmarkHostMatcherWithoutPlaceholder(b *testing.B) {
	req := &http.Request{Host: "localhost"}
	repl := caddy.NewReplacer()
	ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
	req = req.WithContext(ctx)

	match := MatchHost{"localhost"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		match.Match(req)
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

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		match.Match(req)
	}
}
