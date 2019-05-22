package caddyhttp

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"bitbucket.org/lightcodelabs/caddy2"
)

func TestHostMatcher(t *testing.T) {
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
	} {
		req := &http.Request{Host: tc.input}
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
			input:  "foo.ext",
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
		err := tc.match.Provision()
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
		repl := caddy2.NewReplacer()
		ctx := context.WithValue(req.Context(), caddy2.ReplacerCtxKey, repl)
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
		err := tc.match.Provision()
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
		repl := caddy2.NewReplacer()
		ctx := context.WithValue(req.Context(), caddy2.ReplacerCtxKey, repl)
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
