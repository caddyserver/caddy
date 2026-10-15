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
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/internal/filesystems"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/rewrite"
)

type testCase struct {
	path         string
	expectedPath string
	expectedType string
	matched      bool
}

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

	for i, tc := range []testCase{
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
			path:         "/foo.txt?a=b",
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
			expectedPath: "/ملف.txt",
			expectedType: "file",
			matched:      true,
		},
		{
			path:         url.PathEscape("ملف.txt"), // singly-escaped path
			expectedPath: "/ملف.txt",
			expectedType: "file",
			matched:      true,
		},
		{
			path:         url.PathEscape(url.PathEscape("ملف.txt")), // doubly-escaped path
			expectedPath: "/%D9%85%D9%84%D9%81.txt",
			expectedType: "file",
			matched:      true,
		},
		{
			path:         "./with:in-name.txt", // browsers send the request with the path as such
			expectedPath: "/with:in-name.txt",
			expectedType: "file",
			matched:      !isWindows,
		},
	} {
		fileMatcherTest(t, i, tc)
	}
}

func TestFileMatcherNonWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		return
	}

	// this is impossible to test on Windows, but tests a security patch for other platforms
	tc := testCase{
		path:         "/foodir/secr%5Cet.txt",
		expectedPath: "/foodir/secr\\et.txt",
		expectedType: "file",
		matched:      true,
	}

	f, err := os.Create(filepath.Join("testdata", strings.TrimPrefix(tc.expectedPath, "/")))
	if err != nil {
		t.Fatalf("could not create test file: %v", err)
	}
	defer f.Close()
	defer os.Remove(f.Name())

	fileMatcherTest(t, 0, tc)
}

func fileMatcherTest(t *testing.T, i int, tc testCase) {
	m := &MatchFile{
		fsmap:    &filesystems.FileSystemMap{},
		Root:     "./testdata",
		TryFiles: []string{"{http.request.uri.path}", "{http.request.uri.path}/"},
	}

	u, err := url.Parse(tc.path)
	if err != nil {
		t.Errorf("Test %d: parsing path: %v", i, err)
	}

	req := &http.Request{URL: u}
	repl := caddyhttp.NewTestReplacer(req)

	result, err := m.MatchWithError(req)
	if err != nil {
		t.Errorf("Test %d: unexpected error: %v", i, err)
	}
	if result != tc.matched {
		t.Errorf("Test %d: expected match=%t, got %t", i, tc.matched, result)
	}

	rel, ok := repl.Get("http.matchers.file.relative")
	if !ok && result {
		t.Errorf("Test %d: expected replacer value", i)
	}
	if !result {
		return
	}

	if rel != tc.expectedPath {
		t.Errorf("Test %d: actual path: %v, expected: %v", i, rel, tc.expectedPath)
	}

	fileType, _ := repl.Get("http.matchers.file.type")
	if fileType != tc.expectedType {
		t.Errorf("Test %d: actual file type: %v, expected: %v", i, fileType, tc.expectedType)
	}
}

func TestTryFilesRewriteEscapesMatchedPath(t *testing.T) {
	root := t.TempDir()

	tests := []struct {
		name           string
		requestTarget  string
		filename       string
		extraFiles     []string
		wantPath       string
		wantRequestURI string
		skipWindows    bool
	}{
		{
			name:           "question mark in path",
			requestTarget:  "/%3F.html",
			filename:       "?.html",
			wantPath:       "/?.html",
			wantRequestURI: "/%3F.html",
			skipWindows:    true,
		},
		{
			name:           "percent in path",
			requestTarget:  "/%25.html",
			filename:       "%.html",
			wantPath:       "/%.html",
			wantRequestURI: "/%25.html",
		},
		{
			name:           "encoded question mark remains percent-encoded",
			requestTarget:  "/%253F.html",
			filename:       "%3F.html",
			wantPath:       "/%3F.html",
			wantRequestURI: "/%253F.html",
		},
		{
			name:           "question mark in nested path",
			requestTarget:  "/nested/%3F.html",
			filename:       filepath.Join("nested", "?.html"),
			wantPath:       "/nested/?.html",
			wantRequestURI: "/nested/%3F.html",
			skipWindows:    true,
		},
		{
			name:           "encoded slash in filename does not conflict with nesting",
			requestTarget:  "/nested%252Ffile.html",
			filename:       "nested%2Ffile.html",
			extraFiles:     []string{filepath.Join("nested", "file.html")},
			wantPath:       "/nested%2Ffile.html",
			wantRequestURI: "/nested%252Ffile.html",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.skipWindows && runtime.GOOS == "windows" {
				t.Skip("Windows file names cannot contain question marks")
			}

			for _, name := range append([]string{tc.filename}, tc.extraFiles...) {
				filename := filepath.Join(root, name)
				if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
					t.Fatalf("creating test file parent directory: %v", err)
				}
				if err := os.WriteFile(filename, []byte(name), 0o600); err != nil {
					t.Fatalf("writing test file: %v", err)
				}
			}

			m := &MatchFile{
				fsmap:    &filesystems.FileSystemMap{},
				Root:     root,
				TryFiles: []string{"{http.request.uri.path}"},
			}
			req := httptest.NewRequest(http.MethodGet, "http://example.com"+tc.requestTarget, nil)
			repl := caddyhttp.NewTestReplacer(req)

			matched, err := m.MatchWithError(req)
			if err != nil {
				t.Fatalf("matching file: %v", err)
			}
			if !matched {
				t.Fatalf("expected request %s to match %s", tc.requestTarget, tc.filename)
			}

			rewrite.Rewrite{URI: "{http.matchers.file.relative}"}.Rewrite(req, repl)

			if req.URL.Path != tc.wantPath {
				t.Errorf("rewritten path = %q, want %q", req.URL.Path, tc.wantPath)
			}
			if req.RequestURI != tc.wantRequestURI {
				t.Errorf("rewritten request URI = %q, want %q", req.RequestURI, tc.wantRequestURI)
			}
			if req.URL.RawQuery != "" {
				t.Errorf("rewritten raw query = %q, want empty", req.URL.RawQuery)
			}
		})
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
		{
			path:         "/index.php?path={path}&{query}",
			expectedPath: "/index.php",
			expectedType: "file",
			matched:      true,
		},
	} {
		m := &MatchFile{
			fsmap:     &filesystems.FileSystemMap{},
			Root:      "./testdata",
			TryFiles:  []string{"{http.request.uri.path}", "{http.request.uri.path}/index.php"},
			SplitPath: []string{".php"},
		}

		u, err := url.Parse(tc.path)
		if err != nil {
			t.Errorf("Test %d: parsing path: %v", i, err)
		}

		req := &http.Request{URL: u}
		repl := caddyhttp.NewTestReplacer(req)

		result, err := m.MatchWithError(req)
		if err != nil {
			t.Errorf("Test %d: unexpected error: %v", i, err)
		}
		if result != tc.matched {
			t.Errorf("Test %d: expected match=%t, got %t", i, tc.matched, result)
		}

		rel, ok := repl.Get("http.matchers.file.relative")
		if !ok && result {
			t.Errorf("Test %d: expected replacer value", i)
		}
		if !result {
			continue
		}

		if rel != tc.expectedPath {
			t.Errorf("Test %d: actual path: %v, expected: %v", i, rel, tc.expectedPath)
		}

		fileType, _ := repl.Get("http.matchers.file.type")
		if fileType != tc.expectedType {
			t.Errorf("Test %d: actual file type: %v, expected: %v", i, fileType, tc.expectedType)
		}
	}
}

func TestFirstSplit(t *testing.T) {
	m := MatchFile{
		SplitPath: []string{".php"},
		fsmap:     &filesystems.FileSystemMap{},
	}
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

var expressionTests = []struct {
	name              string
	expression        *caddyhttp.MatchExpression
	urlTarget         string
	httpMethod        string
	httpHeader        *http.Header
	wantErr           bool
	wantResult        bool
	clientCertificate []byte
	expectedPath      string
}{
	{
		name: "file error no args (MatchFile)",
		expression: &caddyhttp.MatchExpression{
			Expr: `file()`,
		},
		urlTarget:  "https://example.com/foo.txt",
		wantResult: true,
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
	{
		name: "file match long pattern foo.txt with try_policy (MatchFile)",
		expression: &caddyhttp.MatchExpression{
			Expr: `file({"root": "./testdata", "try_policy": "largest_size", "try_files": ["foo.txt", "large.txt"]})`,
		},
		urlTarget:    "https://example.com/",
		wantResult:   true,
		expectedPath: "/large.txt",
	},
}

func TestMatchExpressionMatch(t *testing.T) {
	for _, tst := range expressionTests {
		tc := tst
		t.Run(tc.name, func(t *testing.T) {
			caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
			defer cancel()
			err := tc.expression.Provision(caddyCtx)
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

			matches, err := tc.expression.MatchWithError(req)
			if err != nil {
				t.Errorf("MatchExpression.Match() error = %v", err)
				return
			}
			if matches != tc.wantResult {
				t.Errorf("MatchExpression.Match() expected to return '%t', for expression : '%s'", tc.wantResult, tc.expression.Expr)
			}

			if tc.expectedPath != "" {
				path, ok := repl.Get("http.matchers.file.relative")
				if !ok {
					t.Errorf("MatchExpression.Match() expected to return path '%s', but got none", tc.expectedPath)
				}
				if path != tc.expectedPath {
					t.Errorf("MatchExpression.Match() expected to return path '%s', but got '%s'", tc.expectedPath, path)
				}
			}
		})
	}
}

// try_policy first_exist_fallback is documented to match unconditionally,
// falling back to the last try_files entry when no earlier candidate exists.
// It must therefore match even when that last entry names a file that is not
// on disk. php_fastcgi relies on this: its generated rewrite route is the only
// step that normalizes r.URL.Path before the FastCGI transport reads it, so a
// matcher that fails here silently removes that normalization.
func TestFirstExistFallbackMatchesWhenFinalFileIsAbsent(t *testing.T) {
	for i, tc := range []struct {
		name         string
		tryFiles     []string
		policy       string
		path         string
		matched      bool
		expectedPath string
	}{
		{
			name:         "fallback matches although the final file is absent",
			tryFiles:     []string{"{http.request.uri.path}", "no-such-index.php"},
			policy:       tryPolicyFirstExistFallback,
			path:         "/does-not-exist.php",
			matched:      true,
			expectedPath: "/no-such-index.php",
		},
		{
			name:         "fallback still prefers an earlier candidate that exists",
			tryFiles:     []string{"{http.request.uri.path}", "no-such-index.php"},
			policy:       tryPolicyFirstExistFallback,
			path:         "/foo.txt",
			matched:      true,
			expectedPath: "/foo.txt",
		},
		{
			name:         "fallback uses the final entry when it does exist",
			tryFiles:     []string{"{http.request.uri.path}", "index.php"},
			policy:       tryPolicyFirstExistFallback,
			path:         "/does-not-exist.php",
			matched:      true,
			expectedPath: "/index.php",
		},
		{
			name:     "first_exist does NOT fall back",
			tryFiles: []string{"{http.request.uri.path}", "no-such-index.php"},
			policy:   tryPolicyFirstExist,
			path:     "/does-not-exist.php",
			matched:  false,
		},
		{
			name:     "empty policy behaves as first_exist",
			tryFiles: []string{"{http.request.uri.path}", "no-such-index.php"},
			policy:   "",
			path:     "/does-not-exist.php",
			matched:  false,
		},
		{
			name:         "fallback uses the final entry literally when its glob expands to nothing",
			tryFiles:     []string{"{http.request.uri.path}", "absent[0-9].php"},
			policy:       tryPolicyFirstExistFallback,
			path:         "/does-not-exist.php",
			matched:      true,
			expectedPath: "/absent[0-9].php",
		},
		{
			name:     "first_exist does not use a pattern expanding to nothing literally",
			tryFiles: []string{"absent[0-9].txt"},
			policy:   tryPolicyFirstExist,
			path:     "/whatever",
			matched:  false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &MatchFile{
				fsmap:     &filesystems.FileSystemMap{},
				Root:      "./testdata",
				TryFiles:  tc.tryFiles,
				TryPolicy: tc.policy,
				SplitPath: []string{".php"},
			}

			u, err := url.Parse(tc.path)
			if err != nil {
				t.Fatalf("Test %d: parsing path: %v", i, err)
			}
			req := &http.Request{URL: u}
			repl := caddyhttp.NewTestReplacer(req)

			result, err := m.MatchWithError(req)
			if err != nil {
				t.Fatalf("Test %d: unexpected error: %v", i, err)
			}
			if result != tc.matched {
				t.Fatalf("Test %d: expected match=%t, got %t", i, tc.matched, result)
			}
			if !result {
				return
			}

			rel, _ := repl.Get("http.matchers.file.relative")
			if rel != tc.expectedPath {
				t.Errorf("Test %d: actual path: %v, expected: %v", i, rel, tc.expectedPath)
			}
		})
	}
}

// Only the final entry of first_exist_fallback may be used without globbing.
// Every other policy must keep expanding patterns as globs, so a file whose
// literal name contains glob metacharacters is not matched by that name.
func TestLiteralGlobNameMatchesOnlyAsFallback(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("globs are not evaluated on Windows")
	}

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "lit[1].txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	for i, tc := range []struct {
		tryFiles          []string
		policy            string
		path              string
		matched           bool
		expectedPath      string
		expectedRemainder string
	}{
		{tryFiles: []string{"lit[1].txt"}, policy: tryPolicyFirstExist, path: "/", matched: false},
		{tryFiles: []string{"lit[1].txt"}, policy: tryPolicyLargestSize, path: "/", matched: false},
		{tryFiles: []string{"lit[1].txt"}, policy: tryPolicySmallestSize, path: "/", matched: false},
		{tryFiles: []string{"lit[1].txt"}, policy: tryPolicyMostRecentlyMod, path: "/", matched: false},
		{
			tryFiles:     []string{"{http.request.uri.path}", "lit[1].txt"},
			policy:       tryPolicyFirstExistFallback,
			path:         "/absent.txt",
			matched:      true,
			expectedPath: "/lit[1].txt",
		},
		{
			// only the final entry is used literally; earlier entries are
			// still globbed, so lit[1].txt is not matched by its literal name
			tryFiles:     []string{"lit[1].txt", "fallback.txt"},
			policy:       tryPolicyFirstExistFallback,
			path:         "/",
			matched:      true,
			expectedPath: "/fallback.txt",
		},
		{
			tryFiles:          []string{"{http.request.uri.path}"},
			policy:            tryPolicyFirstExistFallback,
			path:              "/absent.php/extra",
			matched:           true,
			expectedPath:      "/absent.php",
			expectedRemainder: "/extra",
		},
		{
			// placeholder values are glob-escaped for expansion, but the
			// literal fallback must use the unescaped value
			tryFiles:     []string{"{http.request.uri.path}"},
			policy:       tryPolicyFirstExistFallback,
			path:         "/a[b].txt",
			matched:      true,
			expectedPath: "/a[b].txt",
		},
	} {
		m := &MatchFile{
			fsmap:     &filesystems.FileSystemMap{},
			Root:      root,
			TryFiles:  tc.tryFiles,
			TryPolicy: tc.policy,
			SplitPath: []string{".php"},
		}

		req := &http.Request{URL: &url.URL{Path: tc.path}}
		repl := caddyhttp.NewTestReplacer(req)

		result, err := m.MatchWithError(req)
		if err != nil {
			t.Fatalf("Test %d: unexpected error: %v", i, err)
		}
		if result != tc.matched {
			t.Fatalf("Test %d (%s): expected match=%t, got %t", i, tc.policy, tc.matched, result)
		}
		if !result {
			continue
		}

		rel, _ := repl.Get("http.matchers.file.relative")
		if rel != tc.expectedPath {
			t.Errorf("Test %d: actual path: %v, expected: %v", i, rel, tc.expectedPath)
		}
		rem, _ := repl.Get("http.matchers.file.remainder")
		if rem != tc.expectedRemainder {
			t.Errorf("Test %d: actual remainder: %v, expected: %v", i, rem, tc.expectedRemainder)
		}
	}
}

func TestSizeTryPoliciesWithEmptyFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("globs are not evaluated on Windows")
	}

	root := t.TempDir()
	for name, content := range map[string]string{"empty.txt": "", "big.txt": "some content"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	for i, tc := range []struct {
		policy       string
		tryFiles     []string
		matched      bool
		expectedPath string
	}{
		{policy: tryPolicySmallestSize, tryFiles: []string{"empty.txt", "big.txt"}, matched: true, expectedPath: "/empty.txt"},
		{policy: tryPolicySmallestSize, tryFiles: []string{"big.txt", "empty.txt"}, matched: true, expectedPath: "/empty.txt"},
		{policy: tryPolicySmallestSize, tryFiles: []string{"big.txt"}, matched: true, expectedPath: "/big.txt"},
		{policy: tryPolicyLargestSize, tryFiles: []string{"empty.txt", "big.txt"}, matched: true, expectedPath: "/big.txt"},
		{policy: tryPolicyLargestSize, tryFiles: []string{"empty.txt"}, matched: true, expectedPath: "/empty.txt"},
		{policy: tryPolicyLargestSize, tryFiles: []string{"missing.txt"}, matched: false},
		{policy: tryPolicySmallestSize, tryFiles: []string{"missing.txt"}, matched: false},
	} {
		m := &MatchFile{
			fsmap:     &filesystems.FileSystemMap{},
			Root:      root,
			TryFiles:  tc.tryFiles,
			TryPolicy: tc.policy,
		}

		req := &http.Request{URL: &url.URL{Path: "/"}}
		repl := caddyhttp.NewTestReplacer(req)

		result, err := m.MatchWithError(req)
		if err != nil {
			t.Fatalf("Test %d: unexpected error: %v", i, err)
		}
		if result != tc.matched {
			t.Errorf("Test %d (%s %v): expected match=%t, got %t", i, tc.policy, tc.tryFiles, tc.matched, result)
			continue
		}
		if !result {
			continue
		}
		if rel, _ := repl.Get("http.matchers.file.relative"); rel != tc.expectedPath {
			t.Errorf("Test %d (%s %v): actual path: %v, expected: %v", i, tc.policy, tc.tryFiles, rel, tc.expectedPath)
		}
	}
}

func TestIndexFold(t *testing.T) {
	for i, tc := range []struct {
		haystack, needle string
		expected         int
	}{
		{"index.php", ".php", 5},
		{"index.PHP/x", ".php", 5},
		{"index.php", "php", 6},
		{"index.php", "index.php", 0},
		{"index.php", "z", -1},
		{"ab", "abc", -1},
		{"a", "a", 0},
	} {
		if got := indexFold(tc.haystack, tc.needle); got != tc.expected {
			t.Errorf("Test %d: indexFold(%q, %q) = %d, want %d", i, tc.haystack, tc.needle, got, tc.expected)
		}
	}
}
