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
	"context"
	"net/http"
	"net/url"
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
			expect: newRequest(t, "GET", "/foo"),
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
			rule:   Rewrite{StripPathPrefix: "/%"},
			input:  newRequest(t, "GET", "/%25file"),
			expect: newRequest(t, "GET", "/file"),
		},
		{
			rule:   Rewrite{StripPathPrefix: "/%2"},
			input:  newRequest(t, "GET", "/%252file"),
			expect: newRequest(t, "GET", "/file"),
		},
		{
			rule:   Rewrite{StripPathPrefix: "/%zz"},
			input:  newRequest(t, "GET", "/%25zzfile"),
			expect: newRequest(t, "GET", "/file"),
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
			// the suffix pattern's own '%' must be compared literally: here the
			// path's "%25" decodes to a literal '%', which is not the escape
			// introducer the pattern asks for, so nothing may be stripped
			rule:   Rewrite{StripPathSuffix: "%41"},
			input:  newRequest(t, "GET", "/file%2541"), // decodes to "/file%41"
			expect: newRequest(t, "GET", "/file%2541"),
		},
		{
			rule:   Rewrite{StripPathSuffix: "%2f"},
			input:  newRequest(t, "GET", "/file%252f"), // decodes to "/file%2f"
			expect: newRequest(t, "GET", "/file%252f"),
		},
		{
			rule:   Rewrite{StripPathSuffix: "%25"},
			input:  newRequest(t, "GET", "/file%2525"), // decodes to "/file%25"
			expect: newRequest(t, "GET", "/file%2525"),
		},
		{
			// ...but a path that really does use the pattern's escape is stripped
			rule:   Rewrite{StripPathSuffix: "%41"},
			input:  newRequest(t, "GET", "/file%41"),
			expect: newRequest(t, "GET", "/file"),
		},
		{
			rule:   Rewrite{StripPathSuffix: "%2f"},
			input:  newRequest(t, "GET", "/file%2f"),
			expect: newRequest(t, "GET", "/file"),
		},
		{
			rule:   Rewrite{StripPathSuffix: "%25"},
			input:  newRequest(t, "GET", "/file%25"),
			expect: newRequest(t, "GET", "/file"),
		},
		{
			rule:   Rewrite{StripPathSuffix: "%"},
			input:  newRequest(t, "GET", "/file%25"),
			expect: newRequest(t, "GET", "/file"),
		},
		{
			rule:   Rewrite{StripPathSuffix: "%2"},
			input:  newRequest(t, "GET", "/file%252"),
			expect: newRequest(t, "GET", "/file"),
		},
		{
			rule:   Rewrite{StripPathSuffix: "%zz"},
			input:  newRequest(t, "GET", "/file%25zz"),
			expect: newRequest(t, "GET", "/file"),
		},
		{
			// an escaped suffix pattern must not match the decoded character
			rule:   Rewrite{StripPathSuffix: "%2f"},
			input:  newRequest(t, "GET", "/file/"),
			expect: newRequest(t, "GET", "/file/"),
		},
		{
			// a decoded suffix pattern still matches the path's escaped form
			rule:   Rewrite{StripPathSuffix: ".html"},
			input:  newRequest(t, "GET", "/a%2ehtml"), // %2e == '.'
			expect: newRequest(t, "GET", "/a"),
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

func TestRewriteEscapesFileMatcherRemainder(t *testing.T) {
	for i, tc := range []struct {
		input     string
		remainder string
		expect    string
	}{
		{
			input:     "/index.php/foo/bar?a=b",
			remainder: "/foo/bar",
			expect:    "/index.php/foo/bar?a=b",
		},
		{
			input:     "/index.php/..%252fprivate%252fsecret.txt",
			remainder: "/..%2fprivate%2fsecret.txt",
			expect:    "/index.php/..%252fprivate%252fsecret.txt",
		},
		{
			input:     "/index.php/x%3Fa=evil?a=b",
			remainder: "/x?a=evil",
			expect:    "/index.php/x%3Fa=evil?a=b",
		},
		{
			input:     "/index.php/x%23frag?a=b",
			remainder: "/x#frag",
			expect:    "/index.php/x%23frag?a=b",
		},
	} {
		req := newRequest(t, "GET", tc.input)
		repl := caddy.NewReplacer()
		repl.Set("http.matchers.file.relative", "/index.php")
		repl.Set("http.matchers.file.remainder", tc.remainder)

		Rewrite{URI: "{http.matchers.file.relative}{http.matchers.file.remainder}"}.Rewrite(req, repl)

		if expected, actual := tc.expect, req.URL.RequestURI(); expected != actual {
			t.Errorf("Test %d: Expected URL.RequestURI()='%s' but got '%s'", i, expected, actual)
		}
	}
}

func TestRewriteEscapesDecodedPathPlaceholders(t *testing.T) {
	for _, name := range []string{
		"http.request.uri.path",
		"http.request.uri.path.dir",
		"http.request.uri.path.file",
		"http.request.uri.path.file.base",
		"http.request.uri.path.file.ext",
		"http.request.uri.path.1",
		"http.request.orig_uri.path",
		"http.request.orig_uri.path.dir",
		"http.request.orig_uri.path.file",
		"http.request.orig_uri.path.1",
	} {
		t.Run(name, func(t *testing.T) {
			r := newRequest(t, http.MethodGet, "/pub/%252e%252e/a%3Fb%23c.%25txt")
			repl := caddy.NewReplacer()
			r = caddyhttp.PrepareRequest(r, repl, nil, &caddyhttp.Server{})
			value, ok := repl.Get(name)
			if !ok {
				t.Fatalf("unknown placeholder: %s", name)
			}
			pathValue := caddy.ToString(value)
			Rewrite{URI: "/files{" + name + "}?q={" + name + "}"}.Rewrite(r, repl)
			if r.URL.Path != "/files"+pathValue {
				t.Errorf("Path = %q; want %q", r.URL.Path, "/files"+pathValue)
			}
			if r.URL.RawQuery != "q="+url.QueryEscape(pathValue) || r.URL.Fragment != "" {
				t.Errorf("incorrect query or injected fragment: %s", r.URL)
			}
		})
	}
	for _, tc := range []struct {
		name, target, uri, want string
	}{
		{"original path traversal", "/pub/%252e%252e/priv/secret", "/files{http.request.orig_uri.path}", "/files/pub/%252e%252e/priv/secret"},
		{"original after rewrite", "/pub/%252fsecret", "/files{http.request.orig_uri.path}", "/files/pub/%252fsecret"},
		{"escaped file", "/pub/a%2Fb%3Fc%23d%25", "/files/{http.request.orig_uri.path.file_escaped}", "/files/a/b%3Fc%23d%25"},
		{"whole URI", "/pub/a%3Fb?x=y", "{http.request.orig_uri}", "/pub/a%3Fb?x=y"},
		{"escaped current path", "/pub/%252e%252e", "{http.request.uri.path_escaped}", "/pub/%252e%252e"},
		{"literal escapes", "/pub", "/files/%2e%2e/public?x=y", "/public?x=y"},
		{"encoded extension", "/pub/file.%252f", "/files/{http.request.uri.path.file.ext}", "/files/.%252f"},
		{"literal placeholder text", "/pub/%7Benv.SCAN_PATH_TEST%7D", "/files{http.request.orig_uri.path}", "/files/pub/%7Benv.SCAN_PATH_TEST%7D"},
		{"non-UTF-8 path", "/pub/%ff", "/files{http.request.orig_uri.path}", "/files/pub/%FF"},
		{"Unicode path", "/pub/%C3%84pfel", "/files{http.request.orig_uri.path}", "/files/pub/%C3%84pfel"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRequest(t, http.MethodGet, tc.target)
			repl := caddy.NewReplacer()
			r = caddyhttp.PrepareRequest(r, repl, nil, &caddyhttp.Server{})
			if tc.name == "original after rewrite" {
				Rewrite{URI: "/changed"}.Rewrite(r, repl)
			}
			Rewrite{URI: tc.uri}.Rewrite(r, repl)
			if r.RequestURI != tc.want {
				t.Errorf("RequestURI = %q; want %q", r.RequestURI, tc.want)
			}
		})
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

func TestPathReplacementsCanonicalizeRemainder(t *testing.T) {
	for _, rule := range []struct {
		name string
		rule Rewrite
	}{
		{"substring", Rewrite{URISubstring: []substrReplacer{{Find: "/mount"}}}},
		{"regexp", Rewrite{PathRegexp: []*regexReplacer{{Find: "^/mount", re: regexp.MustCompile("^/mount")}}}},
	} {
		t.Run(rule.name, func(t *testing.T) {
			for _, tc := range []struct {
				target, path, rawPath string
			}{
				{"/mount../secret", "/secret", ""},
				{"/mount..%2fsecret", "/secret", ""},
				{"/mount%2e%2e/secret", "/secret", ""},
				{"/mount", "/", ""},
				{"/mountain", "/ain", ""},
				{"/mount/public", "/public", ""},
				{"/mount/a%2Fb", "/a/b", "/a%2Fb"},
				{"/mount/%252e%252e/secret", "/%2e%2e/secret", ""},
				{"/mount/%ff", "/\xff", "/%ff"},
				{"/unmatched", "/unmatched", ""},
			} {
				t.Run(tc.target, func(t *testing.T) {
					r := newRequest(t, http.MethodGet, tc.target+"?keep=yes")
					repl := caddy.NewReplacer()
					r = r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, repl))
					rule.rule.Rewrite(r, repl)
					if r.URL.Path != tc.path || r.URL.RawPath != tc.rawPath {
						t.Errorf("Path/RawPath = %q/%q; want %q/%q", r.URL.Path, r.URL.RawPath, tc.path, tc.rawPath)
					}
					if r.URL.RawQuery != "keep=yes" || r.RequestURI != r.URL.EscapedPath()+"?keep=yes" {
						t.Errorf("inconsistent request target: %q", r.RequestURI)
					}
					if tc.path == "/secret" && !(caddyhttp.MatchPath{"/secret*"}).Match(r) {
						t.Error("rewritten secret does not match downstream path restriction")
					}
				})
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

func TestRewriteURICanonicalizesChangedPath(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method string
		target string
		header string
		uri    string
		want   string
	}{
		{name: "relative placeholder", target: "/x", header: "../secret", uri: "{http.request.header.X-Path}", want: "/secret"},
		{name: "relative literal", target: "/x", uri: "secret", want: "/secret"},
		{name: "dot segments from placeholder", target: "/x", header: "/public/../secret", uri: "{http.request.header.X-Path}", want: "/secret"},
		{name: "query kept", target: "/x?a=b", header: "../secret", uri: "{http.request.header.X-Path}?{http.request.uri.query}", want: "/secret?a=b"},
		{name: "repeated slashes preserved", target: "/x", uri: "/a//b/", want: "/a//b/"},
		{name: "unchanged path left alone", target: "/a/../b", uri: "{http.request.uri.path}", want: "/a/../b"},
		{name: "OPTIONS star preserved", method: http.MethodOptions, target: "/x", uri: "*", want: "*"},
		{name: "star from placeholder is a path", target: "/x", header: "*", uri: "{http.request.header.X-Path}", want: "/%2A"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			method := tc.method
			if method == "" {
				method = http.MethodGet
			}
			r := newRequest(t, method, tc.target)
			if tc.header != "" {
				r.Header.Set("X-Path", tc.header)
			}
			repl := caddy.NewReplacer()
			r = caddyhttp.PrepareRequest(r, repl, nil, &caddyhttp.Server{})
			Rewrite{URI: tc.uri}.Rewrite(r, repl)
			if r.RequestURI != tc.want {
				t.Errorf("RequestURI = %q; want %q", r.RequestURI, tc.want)
			}
		})
	}
}

func TestRewriteEscapesRegexpCaptures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		target string
		uri    string
		want   string
	}{
		{name: "double-encoded traversal stays data", target: "/pub/%252e%252e%252fsecret", uri: "/files/{http.regexp.pub.1}", want: "/files/%252e%252e%252fsecret"},
		{name: "decoded question mark stays in path", target: "/pub/a%3Fx=1", uri: "/files/{http.regexp.pub.1}", want: "/files/a%3Fx=1"},
		{name: "slashes preserved", target: "/pub/a/b", uri: "/files/{http.regexp.pub.1}", want: "/files/a/b"},
		{name: "configured query unaffected", target: "/pub/a", uri: "/files?id={http.regexp.pub.1}", want: "/files?id=a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRequest(t, http.MethodGet, tc.target)
			repl := caddy.NewReplacer()
			r = caddyhttp.PrepareRequest(r, repl, nil, &caddyhttp.Server{})
			m := caddyhttp.MatchPathRE{MatchRegexp: caddyhttp.MatchRegexp{Name: "pub", Pattern: "^/pub/(.*)$"}}
			if err := m.Provision(caddy.Context{}); err != nil {
				t.Fatal(err)
			}
			if ok, err := m.MatchWithError(r); err != nil || !ok {
				t.Fatalf("path_regexp did not match: %v", err)
			}
			Rewrite{URI: tc.uri}.Rewrite(r, repl)
			if r.RequestURI != tc.want {
				t.Errorf("RequestURI = %q; want %q", r.RequestURI, tc.want)
			}
		})
	}
}
