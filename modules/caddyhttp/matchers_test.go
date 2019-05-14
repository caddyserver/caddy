package caddyhttp

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestHostMatcher(t *testing.T) {
	for i, tc := range []struct {
		match  matchHost
		input  string
		expect bool
	}{
		{
			match:  matchHost{},
			input:  "example.com",
			expect: false,
		},
		{
			match:  matchHost{"example.com"},
			input:  "example.com",
			expect: true,
		},
		{
			match:  matchHost{"example.com"},
			input:  "foo.example.com",
			expect: false,
		},
		{
			match:  matchHost{"example.com"},
			input:  "EXAMPLE.COM",
			expect: true,
		},
		{
			match:  matchHost{"foo.example.com"},
			input:  "foo.example.com",
			expect: true,
		},
		{
			match:  matchHost{"foo.example.com"},
			input:  "bar.example.com",
			expect: false,
		},
		{
			match:  matchHost{"*.example.com"},
			input:  "example.com",
			expect: false,
		},
		{
			match:  matchHost{"*.example.com"},
			input:  "foo.example.com",
			expect: true,
		},
		{
			match:  matchHost{"*.example.com"},
			input:  "foo.bar.example.com",
			expect: false,
		},
		{
			match:  matchHost{"*.example.com", "example.net"},
			input:  "example.net",
			expect: true,
		},
		{
			match:  matchHost{"example.net", "*.example.com"},
			input:  "foo.example.com",
			expect: true,
		},
		{
			match:  matchHost{"*.example.net", "*.*.example.com"},
			input:  "foo.bar.example.com",
			expect: true,
		},
		{
			match:  matchHost{"*.example.net", "sub.*.example.com"},
			input:  "sub.foo.example.com",
			expect: true,
		},
		{
			match:  matchHost{"*.example.net", "sub.*.example.com"},
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
		match  matchPath
		input  string
		expect bool
	}{
		{
			match:  matchPath{},
			input:  "/",
			expect: false,
		},
		{
			match:  matchPath{"/"},
			input:  "/",
			expect: true,
		},
		{
			match:  matchPath{"/foo/bar"},
			input:  "/",
			expect: false,
		},
		{
			match:  matchPath{"/foo/bar"},
			input:  "/foo/bar",
			expect: true,
		},
		{
			match:  matchPath{"/foo/bar/"},
			input:  "/foo/bar",
			expect: false,
		},
		{
			match:  matchPath{"/foo/bar/", "/other"},
			input:  "/other/",
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
		match      matchPathRE
		input      string
		expect     bool
		expectRepl map[string]string
	}{
		{
			match:  matchPathRE{},
			input:  "/",
			expect: true,
		},
		{
			match:  matchPathRE{matchRegexp{Pattern: "/"}},
			input:  "/",
			expect: true,
		},
		{
			match:  matchPathRE{matchRegexp{Pattern: "/foo"}},
			input:  "/foo",
			expect: true,
		},
		{
			match:  matchPathRE{matchRegexp{Pattern: "/foo"}},
			input:  "/foo/",
			expect: true,
		},
		{
			match:  matchPathRE{matchRegexp{Pattern: "/bar"}},
			input:  "/foo/",
			expect: false,
		},
		{
			match:  matchPathRE{matchRegexp{Pattern: "^/bar"}},
			input:  "/foo/bar",
			expect: false,
		},
		{
			match:      matchPathRE{matchRegexp{Pattern: "^/foo/(.*)/baz$", Name: "name"}},
			input:      "/foo/bar/baz",
			expect:     true,
			expectRepl: map[string]string{"name.1": "bar"},
		},
		{
			match:      matchPathRE{matchRegexp{Pattern: "^/foo/(?P<myparam>.*)/baz$", Name: "name"}},
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
		repl := NewReplacer(req, httptest.NewRecorder())
		ctx := context.WithValue(req.Context(), ReplacerCtxKey, repl)
		req = req.WithContext(ctx)

		actual := tc.match.Match(req)
		if actual != tc.expect {
			t.Errorf("Test %d [%v]: Expected %t, got %t for input '%s'",
				i, tc.match.Pattern, tc.expect, actual, tc.input)
			continue
		}

		for key, expectVal := range tc.expectRepl {
			placeholder := fmt.Sprintf("{http.matchers.path_regexp.%s}", key)
			actualVal := repl.Replace(placeholder, "<empty>")
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
		match  matchHeader
		input  http.Header // make sure these are canonical cased (std lib will do that in a real request)
		expect bool
	}{
		{
			match:  matchHeader{"Field": []string{"foo"}},
			input:  http.Header{"Field": []string{"foo"}},
			expect: true,
		},
		{
			match:  matchHeader{"Field": []string{"foo", "bar"}},
			input:  http.Header{"Field": []string{"bar"}},
			expect: true,
		},
		{
			match:  matchHeader{"Field": []string{"foo", "bar"}},
			input:  http.Header{"Alakazam": []string{"kapow"}},
			expect: false,
		},
		{
			match:  matchHeader{"Field": []string{"foo", "bar"}},
			input:  http.Header{"Field": []string{"kapow"}},
			expect: false,
		},
		{
			match:  matchHeader{"Field": []string{"foo", "bar"}},
			input:  http.Header{"Field": []string{"kapow", "foo"}},
			expect: true,
		},
		{
			match:  matchHeader{"Field1": []string{"foo"}, "Field2": []string{"bar"}},
			input:  http.Header{"Field1": []string{"foo"}, "Field2": []string{"bar"}},
			expect: true,
		},
		{
			match:  matchHeader{"field1": []string{"foo"}, "field2": []string{"bar"}},
			input:  http.Header{"Field1": []string{"foo"}, "Field2": []string{"bar"}},
			expect: true,
		},
		{
			match:  matchHeader{"field1": []string{"foo"}, "field2": []string{"bar"}},
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
		match      matchHeaderRE
		input      http.Header // make sure these are canonical cased (std lib will do that in a real request)
		expect     bool
		expectRepl map[string]string
	}{
		{
			match:  matchHeaderRE{"Field": &matchRegexp{Pattern: "foo"}},
			input:  http.Header{"Field": []string{"foo"}},
			expect: true,
		},
		{
			match:  matchHeaderRE{"Field": &matchRegexp{Pattern: "$foo^"}},
			input:  http.Header{"Field": []string{"foobar"}},
			expect: false,
		},
		{
			match:      matchHeaderRE{"Field": &matchRegexp{Pattern: "^foo(.*)$", Name: "name"}},
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
		repl := NewReplacer(req, httptest.NewRecorder())
		ctx := context.WithValue(req.Context(), ReplacerCtxKey, repl)
		req = req.WithContext(ctx)

		actual := tc.match.Match(req)
		if actual != tc.expect {
			t.Errorf("Test %d [%v]: Expected %t, got %t for input '%s'",
				i, tc.match, tc.expect, actual, tc.input)
			continue
		}

		for key, expectVal := range tc.expectRepl {
			placeholder := fmt.Sprintf("{http.matchers.header_regexp.%s}", key)
			actualVal := repl.Replace(placeholder, "<empty>")
			if actualVal != expectVal {
				t.Errorf("Test %d [%v]: Expected placeholder {http.matchers.header_regexp.%s} to be '%s' but got '%s'",
					i, tc.match, key, expectVal, actualVal)
				continue
			}
		}
	}
}
