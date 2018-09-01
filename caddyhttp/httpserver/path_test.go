// Copyright 2015 Light Code Labs, LLC
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

package httpserver

import "testing"

func TestPathMatches(t *testing.T) {
	for i, testcase := range []struct {
		reqPath         Path
		rulePath        string // or "base path" as in Caddyfile docs
		shouldMatch     bool
		caseInsensitive bool
	}{
		{
			reqPath:     "/",
			rulePath:    "/",
			shouldMatch: true,
		},
		{
			reqPath:     "/foo/bar",
			rulePath:    "/foo",
			shouldMatch: true,
		},
		{
			reqPath:     "/foobar",
			rulePath:    "/foo/",
			shouldMatch: false,
		},
		{
			reqPath:     "/foobar",
			rulePath:    "/foo/bar",
			shouldMatch: false,
		},
		{
			reqPath:     "/foo/",
			rulePath:    "/foo/",
			shouldMatch: true,
		},
		{
			reqPath:     "/Foobar",
			rulePath:    "/Foo",
			shouldMatch: true,
		},
		{

			reqPath:     "/FooBar",
			rulePath:    "/Foo",
			shouldMatch: true,
		},
		{
			reqPath:         "/foobar",
			rulePath:        "/FooBar",
			shouldMatch:     true,
			caseInsensitive: true,
		},
		{
			reqPath:     "",
			rulePath:    "/", // a lone forward slash means to match all requests (see issue #1645) - many future test cases related to this issue
			shouldMatch: true,
		},
		{
			reqPath:     "foobar.php",
			rulePath:    "/",
			shouldMatch: true,
		},
		{
			reqPath:     "",
			rulePath:    "",
			shouldMatch: true,
		},
		{
			reqPath:     "/foo/bar",
			rulePath:    "",
			shouldMatch: true,
		},
		{
			reqPath:     "/foo/bar",
			rulePath:    "",
			shouldMatch: true,
		},
		{
			reqPath:     "no/leading/slash",
			rulePath:    "/",
			shouldMatch: true,
		},
		{
			reqPath:     "no/leading/slash",
			rulePath:    "/no/leading/slash",
			shouldMatch: false,
		},
		{
			reqPath:     "no/leading/slash",
			rulePath:    "",
			shouldMatch: true,
		},
		{
			// see issue #1859
			reqPath:     "//double-slash",
			rulePath:    "/double-slash",
			shouldMatch: true,
		},
		{
			reqPath:     "/double//slash",
			rulePath:    "/double/slash",
			shouldMatch: true,
		},
		{
			reqPath:     "//more/double//slashes",
			rulePath:    "/more/double/slashes",
			shouldMatch: true,
		},
		{
			reqPath:     "/path/../traversal",
			rulePath:    "/traversal",
			shouldMatch: true,
		},
		{
			reqPath:     "/path/../traversal",
			rulePath:    "/path",
			shouldMatch: false,
		},
		{
			reqPath:     "/keep-slashes/http://something/foo/bar",
			rulePath:    "/keep-slashes/http://something",
			shouldMatch: true,
		},
	} {
		CaseSensitivePath = !testcase.caseInsensitive
		if got, want := testcase.reqPath.Matches(testcase.rulePath), testcase.shouldMatch; got != want {
			t.Errorf("Test %d: For request path '%s' and base path '%s': expected %v, got %v",
				i, testcase.reqPath, testcase.rulePath, want, got)
		}
	}
}
