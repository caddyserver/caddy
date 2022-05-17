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
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestFileMatcher(t *testing.T) {

	// Windows doesn't like colons in files names
	isWindows := runtime.GOOS == "windows"
	if !isWindows {
		filename := "with:in-name.txt"
		f, err := os.Create("./testdata/" + filename)
		if err != nil {
			t.Fail()
			return
		}
		t.Cleanup(func() {
			os.Remove("./testdata/" + filename)
		})
		f.WriteString(filename)
		f.Close()
	}

	for i, tc := range []struct {
		path         string
		expectedPath string
		expectedType string
		matched      bool
	}{
		{
			path:         "/foo.txt",
			expectedPath: "/foo.txt",
			expectedType: "file",
			matched:      true,
		},
		{
			path:         "/foo.txt/",
			expectedPath: "/foo.txt",
			expectedType: "file",
			matched:      true,
		},
		{
			path:         "/foodir",
			expectedPath: "/foodir/",
			expectedType: "directory",
			matched:      true,
		},
		{
			path:         "/foodir/",
			expectedPath: "/foodir/",
			expectedType: "directory",
			matched:      true,
		},
		{
			path:         "/foodir/foo.txt",
			expectedPath: "/foodir/foo.txt",
			expectedType: "file",
			matched:      true,
		},
		{
			path:    "/missingfile.php",
			matched: false,
		},
		{
			path:         "ملف.txt", // the path file name is not escaped
			expectedPath: "ملف.txt",
			expectedType: "file",
			matched:      true,
		},
		{
			path:         url.PathEscape("ملف.txt"), // singly-escaped path
			expectedPath: "ملف.txt",
			expectedType: "file",
			matched:      true,
		},
		{
			path:         url.PathEscape(url.PathEscape("ملف.txt")), // doubly-escaped path
			expectedPath: "%D9%85%D9%84%D9%81.txt",
			expectedType: "file",
			matched:      true,
		},
		{
			path:         "./with:in-name.txt", // browsers send the request with the path as such
			expectedPath: "with:in-name.txt",
			expectedType: "file",
			matched:      !isWindows,
		},
	} {
		m := &MatchFile{
			Root:     "./testdata",
			TryFiles: []string{"{http.request.uri.path}", "{http.request.uri.path}/"},
		}

		u, err := url.Parse(tc.path)
		if err != nil {
			t.Fatalf("Test %d: parsing path: %v", i, err)
		}

		req := &http.Request{URL: u}
		repl := caddyhttp.NewTestReplacer(req)

		result := m.Match(req)
		if result != tc.matched {
			t.Fatalf("Test %d: expected match=%t, got %t", i, tc.matched, result)
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

		fileType, _ := repl.Get("http.matchers.file.type")
		if fileType != tc.expectedType {
			t.Fatalf("Test %d: actual file type: %v, expected: %v", i, fileType, tc.expectedType)
		}
	}
}

func TestPHPFileMatcher(t *testing.T) {
	for i, tc := range []struct {
		path         string
		expectedPath string
		expectedType string
		matched      bool
	}{
		{
			path:         "/index.php",
			expectedPath: "/index.php",
			expectedType: "file",
			matched:      true,
		},
		{
			path:         "/index.php/somewhere",
			expectedPath: "/index.php",
			expectedType: "file",
			matched:      true,
		},
		{
			path:         "/remote.php",
			expectedPath: "/remote.php",
			expectedType: "file",
			matched:      true,
		},
		{
			path:         "/remote.php/somewhere",
			expectedPath: "/remote.php",
			expectedType: "file",
			matched:      true,
		},
		{
			path:    "/missingfile.php",
			matched: false,
		},
		{
			path:         "/notphp.php.txt",
			expectedPath: "/notphp.php.txt",
			expectedType: "file",
			matched:      true,
		},
		{
			path:         "/notphp.php.txt/",
			expectedPath: "/notphp.php.txt",
			expectedType: "file",
			matched:      true,
		},
		{
			path:    "/notphp.php.txt.suffixed",
			matched: false,
		},
		{
			path:         "/foo.php.php/index.php",
			expectedPath: "/foo.php.php/index.php",
			expectedType: "file",
			matched:      true,
		},
		{
			// See https://github.com/caddyserver/caddy/issues/3623
			path:         "/%E2%C3",
			expectedPath: "/%E2%C3",
			expectedType: "file",
			matched:      false,
		},
	} {
		m := &MatchFile{
			Root:      "./testdata",
			TryFiles:  []string{"{http.request.uri.path}", "{http.request.uri.path}/index.php"},
			SplitPath: []string{".php"},
		}

		u, err := url.Parse(tc.path)
		if err != nil {
			t.Fatalf("Test %d: parsing path: %v", i, err)
		}

		req := &http.Request{URL: u}
		repl := caddyhttp.NewTestReplacer(req)

		result := m.Match(req)
		if result != tc.matched {
			t.Fatalf("Test %d: expected match=%t, got %t", i, tc.matched, result)
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

		fileType, _ := repl.Get("http.matchers.file.type")
		if fileType != tc.expectedType {
			t.Fatalf("Test %d: actual file type: %v, expected: %v", i, fileType, tc.expectedType)
		}
	}
}

func TestFirstSplit(t *testing.T) {
	m := MatchFile{SplitPath: []string{".php"}}
	actual, remainder := m.firstSplit("index.PHP/somewhere")
	expected := "index.PHP"
	expectedRemainder := "/somewhere"
	if actual != expected {
		t.Errorf("Expected split %s but got %s", expected, actual)
	}
	if remainder != expectedRemainder {
		t.Errorf("Expected remainder %s but got %s", expectedRemainder, remainder)
	}
}

var (
	expressionTests = []struct {
		name              string
		expression        *caddyhttp.MatchExpression
		urlTarget         string
		httpMethod        string
		httpHeader        *http.Header
		wantErr           bool
		wantResult        bool
		clientCertificate []byte
	}{
		{
			name: "file error no args (MatchFile)",
			expression: &caddyhttp.MatchExpression{
				Expr: `file()`,
			},
			urlTarget: "https://example.com/foo",
			wantErr:   true,
		},
		{
			name: "file error bad try files (MatchFile)",
			expression: &caddyhttp.MatchExpression{
				Expr: `file({"try_file": ["bad_arg"]})`,
			},
			urlTarget: "https://example.com/foo",
			wantErr:   true,
		},
		{
			name: "file match short pattern index.php (MatchFile)",
			expression: &caddyhttp.MatchExpression{
				Expr: `file("index.php")`,
			},
			urlTarget:  "https://example.com/foo",
			wantResult: true,
		},
		{
			name: "file match short pattern foo.txt (MatchFile)",
			expression: &caddyhttp.MatchExpression{
				Expr: `file({http.request.uri.path})`,
			},
			urlTarget:  "https://example.com/foo.txt",
			wantResult: true,
		},
		{
			name: "file match index.php (MatchFile)",
			expression: &caddyhttp.MatchExpression{
				Expr: `file({"root": "./testdata", "try_files": [{http.request.uri.path}, "/index.php"]})`,
			},
			urlTarget:  "https://example.com/foo",
			wantResult: true,
		},
		{
			name: "file match long pattern foo.txt (MatchFile)",
			expression: &caddyhttp.MatchExpression{
				Expr: `file({"root": "./testdata", "try_files": [{http.request.uri.path}]})`,
			},
			urlTarget:  "https://example.com/foo.txt",
			wantResult: true,
		},
		{
			name: "file match long pattern foo.txt with concatenation (MatchFile)",
			expression: &caddyhttp.MatchExpression{
				Expr: `file({"root": ".", "try_files": ["./testdata" + {http.request.uri.path}]})`,
			},
			urlTarget:  "https://example.com/foo.txt",
			wantResult: true,
		},
		{
			name: "file not match long pattern (MatchFile)",
			expression: &caddyhttp.MatchExpression{
				Expr: `file({"root": "./testdata", "try_files": [{http.request.uri.path}]})`,
			},
			urlTarget:  "https://example.com/nopenope.txt",
			wantResult: false,
		},
	}
)

func TestMatchExpressionMatch(t *testing.T) {
	for _, tst := range expressionTests {
		tc := tst
		t.Run(tc.name, func(t *testing.T) {
			err := tc.expression.Provision(caddy.Context{})
			if err != nil {
				if !tc.wantErr {
					t.Errorf("MatchExpression.Provision() error = %v, wantErr %v", err, tc.wantErr)
				}
				return
			}

			req := httptest.NewRequest(tc.httpMethod, tc.urlTarget, nil)
			if tc.httpHeader != nil {
				req.Header = *tc.httpHeader
			}
			repl := caddyhttp.NewTestReplacer(req)
			repl.Set("http.vars.root", "./testdata")
			ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
			req = req.WithContext(ctx)

			if tc.expression.Match(req) != tc.wantResult {
				t.Errorf("MatchExpression.Match() expected to return '%t', for expression : '%s'", tc.wantResult, tc.expression.Expr)
			}
		})
	}
}
