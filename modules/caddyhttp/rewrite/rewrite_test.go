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
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
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
			rule:   Rewrite{URI: "/api/admin/panel"},
			input:  newRequest(t, "GET", "/api/admin%2Fpanel"),
			expect: newRequest(t, "GET", "/api/admin/panel"),
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
			expect: newRequest(t, "GET", "/"),
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
			// shorter (percent-encoded) path that is not the prefix must be left alone
			rule:   Rewrite{StripPathPrefix: "/aaaaaa"},
			input:  newRequest(t, "GET", "/%61%61"),
			expect: newRequest(t, "GET", "/%61%61"),
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
			rule:   Rewrite{StripPathSuffix: "/suffix"},
			input:  newRequest(t, "GET", "/suffix"),
			expect: newRequest(t, "GET", "/"),
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
			// a decoded suffix pattern must match a percent-encoded path in
			// normalized space, mirroring StripPathPrefix (see the "/a/b/c"
			// vs "/a%2Fb/c/d" case above)
			rule:   Rewrite{StripPathSuffix: "/b/c"},
			input:  newRequest(t, "GET", "/a/b%2Fc"),
			expect: newRequest(t, "GET", "/a"),
		},
		{
			// decoded suffix char matches its percent-encoded form in the path
			rule:   Rewrite{StripPathSuffix: "bc"},
			input:  newRequest(t, "GET", "/a%62c"), // %62 == 'b'
			expect: newRequest(t, "GET", "/a"),
		},
		{
			// an escaped suffix pattern requires the path to use the same
			// escape at that position, so a decoded path must NOT be stripped
			rule:   Rewrite{StripPathSuffix: "%2fsuffix"},
			input:  newRequest(t, "GET", "/foo/bar/suffix"),
			expect: newRequest(t, "GET", "/foo/bar/suffix"),
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
			rule:   Rewrite{URISubstring: []substrReplacer{{Find: "%28", Replace: "("}}},
			input:  newRequest(t, "GET", "/hello/%28%29"),
			expect: newRequest(t, "GET", "/hello/(%29"),
		},
		{
			rule: Rewrite{URISubstring: []substrReplacer{
				{Find: "%28", Replace: "("},
				{Find: "%29", Replace: ")"},
			}},
			input:  newRequest(t, "GET", "/hello/%28%29"),
			expect: newRequest(t, "GET", "/hello/()"),
		},

		{
			rule:   Rewrite{PathRegexp: []*regexReplacer{{Find: "/{2,}", Replace: "/"}}},
			input:  newRequest(t, "GET", "/foo//bar///baz?a=b//c"),
			expect: newRequest(t, "GET", "/foo/bar/baz?a=b//c"),
		},

		// regression tests for GHSA-j8px-rmrx-76h9: when the rewrite URI
		// ends with a literal '?', the first-pass placeholder expansion
		// may produce a path containing attacker-controlled bytes that
		// then get split at '?' and fed into buildQueryString, which runs
		// a SECOND placeholder pass. Bytes injected via a header value (or
		// any other client-controlled placeholder) must not be treated as
		// placeholder syntax during this second pass.
		{
			// literal header value containing placeholder syntax is not re-expanded into query
			rule:   Rewrite{URI: "/serve/{http.request.header.X-Fwd}?"},
			input:  newRequestWithHeader(t, "GET", "/anything", "X-Fwd", "foo?{env.CADDY_REWRITE_TEST_SECRET}=leak"),
			expect: newRequest(t, "GET", "/serve/foo?%7Benv.CADDY_REWRITE_TEST_SECRET%7D=leak"),
		},
		{
			// literal header value with placeholder syntax in query position is not re-expanded
			rule:   Rewrite{URI: "/serve/{http.request.header.X-Fwd}?"},
			input:  newRequestWithHeader(t, "GET", "/anything", "X-Fwd", "ok?key={env.CADDY_REWRITE_TEST_SECRET}"),
			expect: newRequest(t, "GET", "/serve/ok?key=%7Benv.CADDY_REWRITE_TEST_SECRET%7D"),
		},
		{
			// literal header value with embedded file placeholder is not re-expanded
			rule:   Rewrite{URI: "/serve/{http.request.header.X-Fwd}?"},
			input:  newRequestWithHeader(t, "GET", "/anything", "X-Fwd", "ok?path={file./etc/passwd}"),
			expect: newRequest(t, "GET", "/serve/ok?path=%7Bfile./etc/passwd%7D"),
		},

		// '=' delimits a key from its value only once; any further '=' bytes
		// are literal data, such as base64 padding in a signature.
		{
			rule:   Rewrite{URI: "?sig=YWJjZA=="},
			input:  newRequest(t, "GET", "/hello"),
			expect: newRequest(t, "GET", "/hello?sig=YWJjZA=="),
		},
		{
			rule:   Rewrite{URI: "?x=1&sig=YWJjZA=="},
			input:  newRequest(t, "GET", "/hello"),
			expect: newRequest(t, "GET", "/hello?x=1&sig=YWJjZA=="),
		},

		// a query string that arrives via a replacement value is honored even
		// though the configured URI has no literal '?' (see issue #5208).
		{
			rule:   Rewrite{URI: "{http.request.header.X-Accel-Redirect}"},
			input:  newRequestWithHeader(t, "GET", "/orig", "X-Accel-Redirect", "/hello?some=param&some_other=param"),
			expect: newRequest(t, "GET", "/hello?some=param&some_other=param"),
		},
		{
			// an injected query replaces the original one, as a configured query would
			rule:   Rewrite{URI: "{http.request.header.X-Accel-Redirect}"},
			input:  newRequestWithHeader(t, "GET", "/orig?keep=me", "X-Accel-Redirect", "/hello?some=param"),
			expect: newRequest(t, "GET", "/hello?some=param"),
		},
		{
			// a value ending in '?' clears the query, same as configuring a bare '?'
			rule:   Rewrite{URI: "{http.request.header.X-Accel-Redirect}"},
			input:  newRequestWithHeader(t, "GET", "/orig?keep=me", "X-Accel-Redirect", "/hello?"),
			expect: newRequest(t, "GET", "/hello"),
		},
		{
			// no '?' in the value means the query is not touched
			rule:   Rewrite{URI: "{http.request.header.X-Accel-Redirect}"},
			input:  newRequestWithHeader(t, "GET", "/orig?keep=me", "X-Accel-Redirect", "/hello"),
			expect: newRequest(t, "GET", "/hello?keep=me"),
		},
		{
			// an explicitly configured query still wins over an injected one
			rule:   Rewrite{URI: "{http.request.header.X-Accel-Redirect}?a=b"},
			input:  newRequestWithHeader(t, "GET", "/orig", "X-Accel-Redirect", "/hello?some=param"),
			expect: newRequest(t, "GET", "/hello?a=b"),
		},
		{
			// an escaped '?' in the request path does not split the URI, so the
			// implicit rewrites of try_files and php_fastcgi stay safe
			rule:   Rewrite{URI: "{http.request.uri.path}"},
			input:  newRequest(t, "GET", "/bar%3Fbaz?keep=me"),
			expect: newRequest(t, "GET", "/bar%3Fbaz?keep=me"),
		},
		{
			// an S3 presigned URL arriving via a replacement value survives intact
			rule:   Rewrite{URI: "{http.request.header.X-Ph}"},
			input:  newRequestWithHeader(t, "GET", "/orig", "X-Ph", "/f.jpg?X-Amz-Credential=AK%2Ffr-par%2Fs3&X-Amz-Signature=YWJjZA=="),
			expect: newRequest(t, "GET", "/f.jpg?X-Amz-Credential=AK%2Ffr-par%2Fs3&X-Amz-Signature=YWJjZA=="),
		},

		// a fragment that arrives via a replacement value is dropped: everything
		// after '#' is fragment (RFC 3986 section 4.2) and is never sent to the
		// server, so it must not leak into the path or query.
		{
			rule:   Rewrite{URI: "{http.request.header.X-Ph}"},
			input:  newRequestWithHeader(t, "GET", "/orig", "X-Ph", "/hello#frag"),
			expect: newRequest(t, "GET", "/hello"),
		},
		{
			rule:   Rewrite{URI: "{http.request.header.X-Ph}"},
			input:  newRequestWithHeader(t, "GET", "/orig", "X-Ph", "/hello?a=b#frag"),
			expect: newRequest(t, "GET", "/hello?a=b"),
		},
		{
			// a '?' after the injected '#' is fragment, not a query delimiter
			rule:   Rewrite{URI: "{http.request.header.X-Ph}"},
			input:  newRequestWithHeader(t, "GET", "/orig", "X-Ph", "/hello#frag?notquery"),
			expect: newRequest(t, "GET", "/hello"),
		},
		{
			// a configured fragment still wins over an injected one
			rule:   Rewrite{URI: "{http.request.header.X-Ph}#cfgfrag"},
			input:  newRequestWithHeader(t, "GET", "/orig", "X-Ph", "/hello?a=b#frag"),
			expect: newRequest(t, "GET", "/hello?a=b#cfgfrag"),
		},
		{
			// an escaped '#' is not a fragment delimiter and is preserved
			rule:   Rewrite{URI: "{http.request.header.X-Ph}"},
			input:  newRequestWithHeader(t, "GET", "/orig", "X-Ph", "/hello%23frag"),
			expect: newRequest(t, "GET", "/hello%23frag"),
		},
		{
			// a fragment-only value leaves the original query alone
			rule:   Rewrite{URI: "{http.request.header.X-Ph}"},
			input:  newRequestWithHeader(t, "GET", "/orig?keep=me", "X-Ph", "/hello#frag"),
			expect: newRequest(t, "GET", "/hello?keep=me"),
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
		for field, vals := range tc.input.Header {
			repl.Set("http.request.header."+field, strings.Join(vals, ","))
		}

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

func TestQueryOpsRenameNoOpCases(t *testing.T) {
	repl := caddy.NewReplacer()

	for i, tc := range []struct {
		input  *http.Request
		expect map[string][]string
		ops    *queryOps
	}{
		{
			ops: &queryOps{
				Rename: []queryOpsArguments{{Key: "ID", Val: "id"}},
			},
			input:  newRequest(t, "GET", "/?page=test&id=5&test=100"),
			expect: map[string][]string{"id": {"5"}, "page": {"test"}, "test": {"100"}},
		},
		{
			ops: &queryOps{
				Rename: []queryOpsArguments{{Key: "id", Val: "id"}},
			},
			input:  newRequest(t, "GET", "/?page=test&id=5&test=100"),
			expect: map[string][]string{"id": {"5"}, "page": {"test"}, "test": {"100"}},
		},
		{
			ops: &queryOps{
				Rename: []queryOpsArguments{{Key: "ID", Val: "id"}},
			},
			input:  newRequest(t, "GET", "/?page=test&ID=5&test=100"),
			expect: map[string][]string{"id": {"5"}, "page": {"test"}, "test": {"100"}},
		},
		{
			ops: &queryOps{
				Rename: []queryOpsArguments{{Key: "ID", Val: "id"}},
			},
			input:  newRequest(t, "GET", "/?page=test&ID=5&id=7&test=100"),
			expect: map[string][]string{"id": {"5"}, "page": {"test"}, "test": {"100"}},
		},
	} {
		repl.Set("http.request.uri", tc.input.RequestURI)
		repl.Set("http.request.uri.path", tc.input.URL.Path)
		repl.Set("http.request.uri.query", tc.input.URL.RawQuery)

		tc.ops.do(tc.input, repl)

		if actual := tc.input.URL.Query(); !reflect.DeepEqual(tc.expect, map[string][]string(actual)) {
			t.Errorf("Test %d: Expected query=%v but got %v", i, tc.expect, actual)
		}
	}
}

func TestQueryOpsReplaceScopedToKey(t *testing.T) {
	repl := caddy.NewReplacer()

	for i, tc := range []struct {
		input  *http.Request
		expect map[string][]string
		ops    *queryOps
	}{
		{
			// a keyed replace must only touch the named key, even when
			// other keys hold the same value
			ops: &queryOps{
				Replace: []*queryOpsReplacement{{Key: "a", Search: "foo", Replace: "bar"}},
			},
			input:  newRequest(t, "GET", "/?a=foo&b=foo"),
			expect: map[string][]string{"a": {"bar"}, "b": {"foo"}},
		},
		{
			// "*" still replaces across every key
			ops: &queryOps{
				Replace: []*queryOpsReplacement{{Key: "*", Search: "foo", Replace: "bar"}},
			},
			input:  newRequest(t, "GET", "/?a=foo&b=foo"),
			expect: map[string][]string{"a": {"bar"}, "b": {"bar"}},
		},
		{
			// a keyed replace against a missing key is a no-op
			ops: &queryOps{
				Replace: []*queryOpsReplacement{{Key: "missing", Search: "foo", Replace: "bar"}},
			},
			input:  newRequest(t, "GET", "/?a=foo&b=foo"),
			expect: map[string][]string{"a": {"foo"}, "b": {"foo"}},
		},
		{
			// the regexp branch must also stay scoped to the named key
			ops: &queryOps{
				Replace: []*queryOpsReplacement{{Key: "a", SearchRegexp: "f.o", Replace: "bar"}},
			},
			input:  newRequest(t, "GET", "/?a=foo&b=foo"),
			expect: map[string][]string{"a": {"bar"}, "b": {"foo"}},
		},
	} {
		repl.Set("http.request.uri", tc.input.RequestURI)
		repl.Set("http.request.uri.path", tc.input.URL.Path)
		repl.Set("http.request.uri.query", tc.input.URL.RawQuery)

		for _, rep := range tc.ops.Replace {
			if err := rep.Provision(caddy.Context{}); err != nil {
				t.Fatal(err)
			}
		}

		tc.ops.do(tc.input, repl)

		if actual := tc.input.URL.Query(); !reflect.DeepEqual(tc.expect, map[string][]string(actual)) {
			t.Errorf("Test %d: Expected query=%v but got %v", i, tc.expect, actual)
		}
	}
}

func TestStripPathPrefixCanonicalizesRemainder(t *testing.T) {
	for _, tc := range []struct {
		name    string
		target  string
		prefix  string
		path    string
		rawPath string
	}{
		{name: "empty remainder", target: "/mount", prefix: "/mount", path: "/"},
		{name: "mid-segment remainder", target: "/mountain", prefix: "/mount", path: "/ain"},
		{name: "parent segment", target: "/mount../document", prefix: "/mount", path: "/document"},
		{name: "current segment", target: "/mount./document/", prefix: "/mount", path: "/document/"},
		{name: "encoded parent segment", target: "/mount%2e%2e/document", prefix: "/mount", path: "/document"},
		{name: "encoded leading separator", target: "/mount%2Fdocument", prefix: "/mount", path: "/document"},
		{name: "alternate separator encoding", target: "/mount/a%2Fb", prefix: "/mount", path: "/a/b", rawPath: "/a%2Fb"},
		{name: "double-encoded parent segment", target: "/mount/%252e%252e/document", prefix: "/mount", path: "/%2e%2e/document"},
		{name: "non-UTF-8 byte", target: "/mount/%ff", prefix: "/mount", path: "/\xff", rawPath: "/%ff"},
		{name: "repeated separators", target: "/mount//a//b/", prefix: "/mount//", path: "/a//b/"},
		{name: "ordinary remainder", target: "/mount/document", prefix: "/mount", path: "/document"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRequest(t, http.MethodGet, tc.target+"?keep=yes")
			Rewrite{StripPathPrefix: tc.prefix}.Rewrite(r, caddy.NewReplacer())

			if r.URL.Path != tc.path || r.URL.RawPath != tc.rawPath {
				t.Errorf("Path/RawPath = %q/%q; want %q/%q", r.URL.Path, r.URL.RawPath, tc.path, tc.rawPath)
			}
			if r.URL.RawQuery != "keep=yes" || r.RequestURI != r.URL.EscapedPath()+"?keep=yes" {
				t.Errorf("query or request target changed inconsistently: %q", r.RequestURI)
			}
		})
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

func newRequestWithHeader(t *testing.T, method, uri, headerKey, headerVal string) *http.Request {
	req := newRequest(t, method, uri)
	req.Header.Set(headerKey, headerVal)
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

func TestQueryComponentEnd(t *testing.T) {
	for _, tc := range []struct {
		name, input, component string
		wroteVal, ampIsNext    bool
	}{
		{name: "empty", wroteVal: true},
		{name: "whole key", input: "key", component: "key", wroteVal: true},
		{name: "whole value", input: "value", component: "value"},
		{name: "key equals", input: "key=value&next=ok", component: "key", wroteVal: true},
		{name: "value equals", input: "a=b&next=ok", component: "a=b", ampIsNext: true},
		{name: "key ampersand", input: "key&next=ok", component: "key", wroteVal: true, ampIsNext: true},
		{name: "empty key", input: "=value", wroteVal: true},
		{name: "empty value", input: "&next=ok", ampIsNext: true},
		{name: "ordinary reference", input: "{key&name}=value", component: "{key&name}", wroteVal: true},
		{name: "default key", input: "{missing:-a=b&c}=value", component: "{missing:-a=b&c}", wroteVal: true},
		{name: "default value", input: "{missing:-a=b&c}&next=ok", component: "{missing:-a=b&c}", ampIsNext: true},
		{name: "nested default", input: "{missing:-{other:-a=b&c}}&next=ok", component: "{missing:-{other:-a=b&c}}", ampIsNext: true},
		{name: "adjacent references", input: "{one}{two:-a&b}=value", component: "{one}{two:-a&b}", wroteVal: true},
		{name: "escaped closing brace in default", input: `{missing:-a\}&b}=value`, component: `{missing:-a\}&b}`, wroteVal: true},
		{name: "escaped opening brace", input: `\{missing:-a&b}=value`, component: `\{missing:-a`, wroteVal: true, ampIsNext: true},
		{name: "double backslash protects opening brace", input: `\\{missing:-a&b}=value`, component: `\\{missing:-a`, wroteVal: true, ampIsNext: true},
		{name: "unclosed reference", input: "{key&next=ok", component: "{key", wroteVal: true, ampIsNext: true},
		{name: "malformed default", input: "{missing:-a&next=ok", component: "{missing:-a", wroteVal: true, ampIsNext: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			end, ampIsNext := queryComponentEnd(tc.input, tc.wroteVal)
			if end != len(tc.component) || ampIsNext != tc.ampIsNext {
				t.Fatalf("component end = %d, ampersand next = %v; want %d, %v", end, ampIsNext, len(tc.component), tc.ampIsNext)
			}
		})
	}
}

func TestRewritePlaceholderDefaultQueries(t *testing.T) {
	for _, tc := range []struct {
		name, requestURI, rewriteURI, wantQuery string
	}{
		{"literal spaces", "/orig", "/dest?q={missing:-two words}", "q=two+words"},
		{"literal delimiters", "/orig", "/dest?q={missing:-a b=c?d#e&f}&next=ok", "q=a+b%3Dc%3Fd%23e%26f&next=ok"},
		{"literal delimiters in key", "/orig", "/dest?{missing:-a=b?c#d&f}=ok", "a%3Db%3Fc%23d%26f=ok"},
		{"nested encoded query", "/orig?a=two+words&b=%3F", "/dest?{missing:-{http.request.uri.query}}&next=ok", "a=two+words&b=%3F&next=ok"},
		{"empty query literal fallback", "/orig", "/dest?{http.request.uri.query:-two words=?#}", "two+words%3D%3F%23"},
		{"empty query fallback in value", "/orig", "/dest?q={http.request.uri.query:-two words=?#}", "q=two+words%3D%3F%23"},
		{"nested provider text stays literal", "/orig", "/dest?q={missing:-{http.request.header.X-Literal}}", "q=%7Bdanger%7D"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := newRequest(t, http.MethodGet, tc.requestURI)
			req.Header.Set("X-Literal", "{danger}")
			repl := caddyhttp.NewTestReplacer(req)
			repl.Set("danger", "expanded")
			rule := Rewrite{URI: tc.rewriteURI}
			rule.Rewrite(req, repl)
			if req.URL.Path != "/dest" || req.URL.RawQuery != tc.wantQuery || req.URL.Fragment != "" {
				t.Fatalf("rewritten URL = %s; want path /dest, query %q, empty fragment", req.URL, tc.wantQuery)
			}
		})
	}
}

func TestRewritePlaceholderDefaultPathValuesStayLiteral(t *testing.T) {
	for _, uri := range []string{
		"/dest/{http.request.header.X-Literal:-fallback}",
		"/dest/{missing:-{http.request.header.X-Literal}}",
	} {
		t.Run(uri, func(t *testing.T) {
			req := newRequest(t, http.MethodGet, "/orig")
			req.Header.Set("X-Literal", "{danger}")
			repl := caddyhttp.NewTestReplacer(req)
			repl.Set("danger", "expanded")
			rule := Rewrite{URI: uri}
			rule.Rewrite(req, repl)
			if req.URL.Path != "/dest/{danger}" || req.URL.RawQuery != "" || req.URL.Fragment != "" {
				t.Fatalf("rewritten URL = %s; provider text must remain literal", req.URL)
			}
		})
	}
}

func TestRewritePlaceholderDefaultPathDelimiters(t *testing.T) {
	for _, tc := range []struct {
		name, requestURI, rewriteURI, wantPath, wantQuery string
	}{
		{"composite path preserves escaped question mark", "/a%3Fb", "{missing:-/prefix{http.request.uri.path}}", "/prefix/a?b", ""},
		{"composite path preserves all encoded delimiters", "/a%3Fb%23c%25d%26e%3Df?keep=me", "{missing:-/prefix{http.request.uri.path}}", "/prefix/a?b#c%d&e=f", "keep=me"},
		{"nested path preserves encoded percent", "/a%252Fb?keep=me", "{missing:-{http.request.uri.path}}", "/a%2Fb", "keep=me"},
		{"literal fallback sets query", "/orig", "{missing:-/home?lang=en}", "/home", "lang=en"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := newRequest(t, http.MethodGet, tc.requestURI)
			repl := caddyhttp.NewTestReplacer(req)
			rule := Rewrite{URI: tc.rewriteURI}
			rule.Rewrite(req, repl)
			if req.URL.Path != tc.wantPath || req.URL.RawQuery != tc.wantQuery {
				t.Fatalf("rewritten URL = %s; want path %q and query %q", req.URL, tc.wantPath, tc.wantQuery)
			}
		})
	}
}

func TestRewriteDefaultsDoNotEvaluateProviderExpressions(t *testing.T) {
	t.Setenv("CADDY_DEFAULT_AUDIT_SECRET", "default-audit-secret-canary")
	for _, payload := range []string{
		`{env.CADDY_DEFAULT_AUDIT_SECRET}`,
		`/target?token={env.CADDY_DEFAULT_AUDIT_SECRET}`,
		`/target?token={missing:-{env.CADDY_DEFAULT_AUDIT_SECRET}}`,
		`/target?token=%7Benv.CADDY_DEFAULT_AUDIT_SECRET%7D`,
	} {
		for _, uri := range []string{
			`{http.request.header.X-Audit:-/fallback}`,
			`{missing:-{http.request.header.X-Audit}}`,
			`{missing:-/prefix{http.request.header.X-Audit}suffix}`,
			`/target?q={missing:-{http.request.header.X-Audit}}`,
			`/target?{missing:-{http.request.header.X-Audit}}`,
			`/target#{missing:-{http.request.header.X-Audit}}`,
		} {
			req := newRequest(t, http.MethodGet, "/orig")
			req.Header.Set("X-Audit", payload)
			repl := caddyhttp.NewTestReplacer(req)
			Rewrite{URI: uri}.Rewrite(req, repl)
			if strings.Contains(req.URL.String(), "default-audit-secret-canary") {
				t.Fatalf("provider expression evaluated: URI %q, payload %q, result %s", uri, payload, req.URL)
			}
		}
	}
}

func TestRewriteEscapedOpeningBraceDelimiters(t *testing.T) {
	for _, tc := range []struct{ uri, path, query, fragment string }{
		{`/dest?q=\{missing:-a#fragment}`, "/dest", `q={missing:-a`, "fragment}"},
		{`/dest?q=\\{missing:-a#fragment}`, "/dest", `q=\{missing:-a`, "fragment}"},
		{`/dest/\{missing:-a?b=c#fragment}`, "/dest/{missing:-a", "b=c", "fragment}"},
	} {
		t.Run(tc.uri, func(t *testing.T) {
			req := newRequest(t, http.MethodGet, "/orig")
			repl := caddyhttp.NewTestReplacer(req)
			Rewrite{URI: tc.uri}.Rewrite(req, repl)
			if req.URL.Path != tc.path || req.URL.RawQuery != tc.query || req.URL.Fragment != tc.fragment {
				t.Fatalf("rewritten URL = %s; want path %q, query %q, fragment %q", req.URL, tc.path, tc.query, tc.fragment)
			}
		})
	}
}
