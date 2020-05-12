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

package fileserver

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestPhpFileMatcher(t *testing.T) {

	for i, tc := range []struct {
		path string
		expectedPath string
		matched bool
	}{
		{
			path: "/index.php",
			expectedPath: "/index.php",
			matched: true,
		},
		{
			path: "/index.php/somewhere",
			expectedPath: "/index.php",
			matched: true,
		},
		{
			path: "/remote.php",
			expectedPath: "/remote.php",
			matched: true,
		},
		{
			path: "/remote.php/somewhere",
			expectedPath: "/remote.php",
			matched: true,
		},
		{
			path: "/missingfile.php",
			matched: false,
		},
		{
			path: "/notphp.php.txt",
			expectedPath: "/notphp.php.txt",
			matched: true,
		},
		{
			path: "/notphp.php.txt/",
			expectedPath: "/notphp.php.txt",
			matched: true,
		},
		{
			path: "/notphp.php.txt.suffixed",
			matched: false,
		},
		{
			path: "/foo.php.php/index.php",
			expectedPath: "/foo.php.php/index.php",
			matched: true,
		},
	} {
		m := &MatchFile{
			Root:      "./testdata",
			TryFiles:  []string{"{http.request.uri.path}"},
			SplitPath: []string{".php"},
		}

		req := &http.Request{URL: &url.URL{Path: tc.path}}
		repl := caddyhttp.NewTestReplacer(req)

		result := m.Match(req)
		if result != tc.matched {
			t.Fatalf("Test %d: match bool result: %v, expected: %v", i, result, tc.matched)
		}

		rel, ok := repl.Get("http.matchers.file.relative")
		if !ok && result {
			t.Fatalf("Test %d: expected replacer value", i)
		}
		if !result {
			continue
		}

		if rel != tc.expectedPath {
			t.Fatalf("Test %d: actual path: %v, expected: %v", i, rel, tc.expectedPath)
		}
	}
}