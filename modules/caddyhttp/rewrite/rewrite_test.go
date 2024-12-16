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

package rewrite

import (
	"net/http"
	"regexp"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

func TestRewrite(t *testing.T) {
	repl := caddy.NewReplacer()

	for i, tc := range []struct {
		input, expect *http.Request
		rule          Rewrite
	}{
		{
			input:  newRequest(t, "GET", "/"),
			expect: newRequest(t, "GET", "/"),
		},
		{
			rule:   Rewrite{Method: "GET", URI: "/"},
			input:  newRequest(t, "GET", "/"),
			expect: newRequest(t, "GET", "/"),
		},
		{
			rule:   Rewrite{Method: "POST"},
			input:  newRequest(t, "GET", "/"),
			expect: newRequest(t, "POST", "/"),
		},

		{
			rule:   Rewrite{URI: "/foo"},
			input:  newRequest(t, "GET", "/"),
			expect: newRequest(t, "GET", "/foo"),
		},
		{
			rule:   Rewrite{URI: "/foo"},
			input:  newRequest(t, "GET", "/bar"),
			expect: newRequest(t, "GET", "/foo"),
		},
		{
			rule:   Rewrite{URI: "foo"},
			input:  newRequest(t, "GET", "/"),
			expect: newRequest(t, "GET", "foo"),
		},
		{
			rule:   Rewrite{URI: "{http.request.uri}"},
			input:  newRequest(t, "GET", "/bar%3Fbaz?c=d"),
			expect: newRequest(t, "GET", "/bar%3Fbaz?c=d"),
		},
		{
			rule:   Rewrite{URI: "{http.request.uri.path}"},
			input:  newRequest(t, "GET", "/bar%3Fbaz"),
			expect: newRequest(t, "GET", "/bar%3Fbaz"),
		},
		{
			rule:   Rewrite{URI: "/foo{http.request.uri.path}"},
			input:  newRequest(t, "GET", "/bar"),
			expect: newRequest(t, "GET", "/foo/bar"),
		},
		{
			rule:   Rewrite{URI: "/index.php?p={http.request.uri.path}"},
			input:  newRequest(t, "GET", "/foo/bar"),
			expect: newRequest(t, "GET", "/index.php?p=%2Ffoo%2Fbar"),
		},
		{
			rule:   Rewrite{URI: "?a=b&{http.request.uri.query}"},
			input:  newRequest(t, "GET", "/"),
			expect: newRequest(t, "GET", "/?a=b"),
		},
		{
			rule:   Rewrite{URI: "/?c=d"},
			input:  newRequest(t, "GET", "/"),
			expect: newRequest(t, "GET", "/?c=d"),
		},
		{
			rule:   Rewrite{URI: "/?c=d"},
			input:  newRequest(t, "GET", "/?a=b"),
			expect: newRequest(t, "GET", "/?c=d"),
		},
		{
			rule:   Rewrite{URI: "?c=d"},
			input:  newRequest(t, "GET", "/foo"),
			expect: newRequest(t, "GET", "/foo?c=d"),
		},
		{
			rule:   Rewrite{URI: "/?c=d"},
			input:  newRequest(t, "GET", "/foo"),
			expect: newRequest(t, "GET", "/?c=d"),
		},
		{
			rule:   Rewrite{URI: "/?{http.request.uri.query}&c=d"},
			input:  newRequest(t, "GET", "/"),
			expect: newRequest(t, "GET", "/?c=d"),
		},
		{
			rule:   Rewrite{URI: "/foo?{http.request.uri.query}&c=d"},
			input:  newRequest(t, "GET", "/"),
			expect: newRequest(t, "GET", "/foo?c=d"),
		},
		{
			rule:   Rewrite{URI: "?{http.request.uri.query}&c=d"},
			input:  newRequest(t, "GET", "/foo"),
			expect: newRequest(t, "GET", "/foo?c=d"),
		},
		{
			rule:   Rewrite{URI: "{http.request.uri.path}?{http.request.uri.query}&c=d"},
			input:  newRequest(t, "GET", "/foo"),
			expect: newRequest(t, "GET", "/foo?c=d"),
		},
		{
			rule:   Rewrite{URI: "{http.request.uri.path}?{http.request.uri.query}&c=d"},
			input:  newRequest(t, "GET", "/foo"),
			expect: newRequest(t, "GET", "/foo?c=d"),
		},
		{
			rule:   Rewrite{URI: "/index.php?{http.request.uri.query}&c=d"},
			input:  newRequest(t, "GET", "/foo"),
			expect: newRequest(t, "GET", "/index.php?c=d"),
		},
		{
			rule:   Rewrite{URI: "?a=b&c=d"},
			input:  newRequest(t, "GET", "/foo"),
			expect: newRequest(t, "GET", "/foo?a=b&c=d"),
		},
		{
			rule:   Rewrite{URI: "/index.php?{http.request.uri.query}&c=d"},
			input:  newRequest(t, "GET", "/?a=b"),
			expect: newRequest(t, "GET", "/index.php?a=b&c=d"),
		},
		{
			rule:   Rewrite{URI: "/index.php?c=d&{http.request.uri.query}"},
			input:  newRequest(t, "GET", "/?a=b"),
			expect: newRequest(t, "GET", "/index.php?c=d&a=b"),
		},
		{
			rule:   Rewrite{URI: "/index.php?{http.request.uri.query}&p={http.request.uri.path}"},
			input:  newRequest(t, "GET", "/foo/bar?a=b"),
			expect: newRequest(t, "GET", "/index.php?a=b&p=%2Ffoo%2Fbar"),
		},
		{
			rule:   Rewrite{URI: "{http.request.uri.path}?"},
			input:  newRequest(t, "GET", "/foo/bar?a=b&c=d"),
			expect: newRequest(t, "GET", "/foo/bar"),
		},
		{
			rule:   Rewrite{URI: "?qs={http.request.uri.query}"},
			input:  newRequest(t, "GET", "/foo?a=b&c=d"),
			expect: newRequest(t, "GET", "/foo?qs=a%3Db%26c%3Dd"),
		},
		{
			rule:   Rewrite{URI: "/foo?{http.request.uri.query}#frag"},
			input:  newRequest(t, "GET", "/foo/bar?a=b"),
			expect: newRequest(t, "GET", "/foo?a=b#frag"),
		},
		{
			rule:   Rewrite{URI: "/foo{http.request.uri}"},
			input:  newRequest(t, "GET", "/bar?a=b"),
			expect: newRequest(t, "GET", "/foo/bar?a=b"),
		},
		{
			rule:   Rewrite{URI: "/foo{http.request.uri}"},
			input:  newRequest(t, "GET", "/bar"),
			expect: newRequest(t, "GET", "/foo/bar"),
		},
		{
			rule:   Rewrite{URI: "/foo{http.request.uri}?c=d"},
			input:  newRequest(t, "GET", "/bar?a=b"),
			expect: newRequest(t, "GET", "/foo/bar?c=d"),
		},
		{
			rule:   Rewrite{URI: "/foo{http.request.uri}?{http.request.uri.query}&c=d"},
			input:  newRequest(t, "GET", "/bar?a=b"),
			expect: newRequest(t, "GET", "/foo/bar?a=b&c=d"),
		},
		{
			rule:   Rewrite{URI: "{http.request.uri}"},
			input:  newRequest(t, "GET", "/bar?a=b"),
			expect: newRequest(t, "GET", "/bar?a=b"),
		},
		{
			rule:   Rewrite{URI: "{http.request.uri.path}bar?c=d"},
			input:  newRequest(t, "GET", "/foo/?a=b"),
			expect: newRequest(t, "GET", "/foo/bar?c=d"),
		},
		{
			rule:   Rewrite{URI: "/i{http.request.uri}"},
			input:  newRequest(t, "GET", "/%C2%B7%E2%88%B5.png"),
			expect: newRequest(t, "GET", "/i/%C2%B7%E2%88%B5.png"),
		},
		{
			rule:   Rewrite{URI: "/i{http.request.uri}"},
			input:  newRequest(t, "GET", "/·∵.png?a=b"),
			expect: newRequest(t, "GET", "/i/%C2%B7%E2%88%B5.png?a=b"),
		},
		{
			rule:   Rewrite{URI: "/i{http.request.uri}"},
			input:  newRequest(t, "GET", "/%C2%B7%E2%88%B5.png?a=b"),
			expect: newRequest(t, "GET", "/i/%C2%B7%E2%88%B5.png?a=b"),
		},
		{
			rule:   Rewrite{URI: "/bar#?"},
			input:  newRequest(t, "GET", "/foo#fragFirst?c=d"), // not a valid query string (is part of fragment)
			expect: newRequest(t, "GET", "/bar#?"),             // I think this is right? but who knows; std lib drops fragment when parsing
		},
		{
			rule:   Rewrite{URI: "/bar"},
			input:  newRequest(t, "GET", "/foo#fragFirst?c=d"),
			expect: newRequest(t, "GET", "/bar#fragFirst?c=d"),
		},

		{
			rule:   Rewrite{StripPathPrefix: "/prefix"},
			input:  newRequest(t, "GET", "/foo/bar"),
			expect: newRequest(t, "GET", "/foo/bar"),
		},
		{
			rule:   Rewrite{StripPathPrefix: "/prefix"},
			input:  newRequest(t, "GET", "/prefix/foo/bar"),
			expect: newRequest(t, "GET", "/foo/bar"),
		},
		{
			rule:   Rewrite{StripPathPrefix: "prefix"},
			input:  newRequest(t, "GET", "/prefix/foo/bar"),
			expect: newRequest(t, "GET", "/foo/bar"),
		},
		{
			rule:   Rewrite{StripPathPrefix: "/prefix"},
			input:  newRequest(t, "GET", "/prefix"),
			expect: newRequest(t, "GET", ""),
		},
		{
			rule:   Rewrite{StripPathPrefix: "/prefix"},
			input:  newRequest(t, "GET", "/"),
			expect: newRequest(t, "GET", "/"),
		},
		{
			rule:   Rewrite{StripPathPrefix: "/prefix"},
			input:  newRequest(t, "GET", "/prefix/foo%2Fbar"),
			expect: newRequest(t, "GET", "/foo%2Fbar"),
		},
		{
			rule:   Rewrite{StripPathPrefix: "/prefix"},
			input:  newRequest(t, "GET", "/foo/prefix/bar"),
			expect: newRequest(t, "GET", "/foo/prefix/bar"),
		},
		{
			rule: Rewrite{StripPathPrefix: "//prefix"},
			// scheme and host needed for URL parser to succeed in setting up test
			input:  newRequest(t, "GET", "http://host//prefix/foo/bar"),
			expect: newRequest(t, "GET", "http://host/foo/bar"),
		},
		{
			rule:   Rewrite{StripPathPrefix: "//prefix"},
			input:  newRequest(t, "GET", "/prefix/foo/bar"),
			expect: newRequest(t, "GET", "/prefix/foo/bar"),
		},
		{
			rule:   Rewrite{StripPathPrefix: "/a%2Fb/c"},
			input:  newRequest(t, "GET", "/a%2Fb/c/d"),
			expect: newRequest(t, "GET", "/d"),
		},
		{
			rule:   Rewrite{StripPathPrefix: "/a%2Fb/c"},
			input:  newRequest(t, "GET", "/a%2fb/c/d"),
			expect: newRequest(t, "GET", "/d"),
		},
		{
			rule:   Rewrite{StripPathPrefix: "/a/b/c"},
			input:  newRequest(t, "GET", "/a%2Fb/c/d"),
			expect: newRequest(t, "GET", "/d"),
		},
		{
			rule:   Rewrite{StripPathPrefix: "/a%2Fb/c"},
			input:  newRequest(t, "GET", "/a/b/c/d"),
			expect: newRequest(t, "GET", "/a/b/c/d"),
		},
		{
			rule:   Rewrite{StripPathPrefix: "//a%2Fb/c"},
			input:  newRequest(t, "GET", "/a/b/c/d"),
			expect: newRequest(t, "GET", "/a/b/c/d"),
		},

		{
			rule:   Rewrite{StripPathSuffix: "/suffix"},
			input:  newRequest(t, "GET", "/foo/bar"),
			expect: newRequest(t, "GET", "/foo/bar"),
		},
		{
			rule:   Rewrite{StripPathSuffix: "suffix"},
			input:  newRequest(t, "GET", "/foo/bar/suffix"),
			expect: newRequest(t, "GET", "/foo/bar/"),
		},
		{
			rule:   Rewrite{StripPathSuffix: "suffix"},
			input:  newRequest(t, "GET", "/foo%2Fbar/suffix"),
			expect: newRequest(t, "GET", "/foo%2Fbar/"),
		},
		{
			rule:   Rewrite{StripPathSuffix: "%2fsuffix"},
			input:  newRequest(t, "GET", "/foo%2Fbar%2fsuffix"),
			expect: newRequest(t, "GET", "/foo%2Fbar"),
		},
		{
			rule:   Rewrite{StripPathSuffix: "/suffix"},
			input:  newRequest(t, "GET", "/foo/suffix/bar"),
			expect: newRequest(t, "GET", "/foo/suffix/bar"),
		},

		{
			rule:   Rewrite{URISubstring: []substrReplacer{{Find: "findme", Replace: "replaced"}}},
			input:  newRequest(t, "GET", "/foo/bar"),
			expect: newRequest(t, "GET", "/foo/bar"),
		},
		{
			rule:   Rewrite{URISubstring: []substrReplacer{{Find: "findme", Replace: "replaced"}}},
			input:  newRequest(t, "GET", "/foo/findme/bar"),
			expect: newRequest(t, "GET", "/foo/replaced/bar"),
		},
		{
			rule:   Rewrite{URISubstring: []substrReplacer{{Find: "findme", Replace: "replaced"}}},
			input:  newRequest(t, "GET", "/foo/findme%2Fbar"),
			expect: newRequest(t, "GET", "/foo/replaced%2Fbar"),
		},

		{
			rule:   Rewrite{PathRegexp: []*regexReplacer{{Find: "/{2,}", Replace: "/"}}},
			input:  newRequest(t, "GET", "/foo//bar///baz?a=b//c"),
			expect: newRequest(t, "GET", "/foo/bar/baz?a=b//c"),
		},
	} {
		// copy the original input just enough so that we can
		// compare it after the rewrite to see if it changed
		urlCopy := *tc.input.URL
		originalInput := &http.Request{
			Method:     tc.input.Method,
			RequestURI: tc.input.RequestURI,
			URL:        &urlCopy,
		}

		// populate the replacer just enough for our tests
		repl.Set("http.request.uri", tc.input.RequestURI)
		repl.Set("http.request.uri.path", tc.input.URL.Path)
		repl.Set("http.request.uri.query", tc.input.URL.RawQuery)

		// we can't directly call Provision() without a valid caddy.Context
		// (TODO: fix that) so here we ad-hoc compile the regex
		for _, rep := range tc.rule.PathRegexp {
			re, err := regexp.Compile(rep.Find)
			if err != nil {
				t.Fatal(err)
			}
			rep.re = re
		}

		changed := tc.rule.Rewrite(tc.input, repl)

		if expected, actual := !reqEqual(originalInput, tc.input), changed; expected != actual {
			t.Errorf("Test %d: Expected changed=%t but was %t", i, expected, actual)
		}
		if expected, actual := tc.expect.Method, tc.input.Method; expected != actual {
			t.Errorf("Test %d: Expected Method='%s' but got '%s'", i, expected, actual)
		}
		if expected, actual := tc.expect.RequestURI, tc.input.RequestURI; expected != actual {
			t.Errorf("Test %d: Expected RequestURI='%s' but got '%s'", i, expected, actual)
		}
		if expected, actual := tc.expect.URL.String(), tc.input.URL.String(); expected != actual {
			t.Errorf("Test %d: Expected URL='%s' but got '%s'", i, expected, actual)
		}
		if expected, actual := tc.expect.URL.RequestURI(), tc.input.URL.RequestURI(); expected != actual {
			t.Errorf("Test %d: Expected URL.RequestURI()='%s' but got '%s'", i, expected, actual)
		}
		if expected, actual := tc.expect.URL.Fragment, tc.input.URL.Fragment; expected != actual {
			t.Errorf("Test %d: Expected URL.Fragment='%s' but got '%s'", i, expected, actual)
		}
	}
}

func newRequest(t *testing.T, method, uri string) *http.Request {
	req, err := http.NewRequest(method, uri, nil)
	if err != nil {
		t.Fatalf("error creating request: %v", err)
	}
	req.RequestURI = req.URL.RequestURI() // simulate incoming request
	return req
}

// reqEqual if r1 and r2 are equal enough for our purposes.
func reqEqual(r1, r2 *http.Request) bool {
	if r1.Method != r2.Method {
		return false
	}
	if r1.RequestURI != r2.RequestURI {
		return false
	}
	if (r1.URL == nil && r2.URL != nil) || (r1.URL != nil && r2.URL == nil) {
		return false
	}
	if r1.URL == nil && r2.URL == nil {
		return true
	}
	return r1.URL.Scheme == r2.URL.Scheme &&
		r1.URL.Host == r2.URL.Host &&
		r1.URL.Path == r2.URL.Path &&
		r1.URL.RawPath == r2.URL.RawPath &&
		r1.URL.RawQuery == r2.URL.RawQuery &&
		r1.URL.Fragment == r2.URL.Fragment
}
