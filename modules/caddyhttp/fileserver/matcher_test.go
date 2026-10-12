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
	"strconv"
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

func TestCELFileProviderTextRemainsLiteral(t *testing.T) {
	const token = "{env.CADDY_CEL_FILE_TEST}"
	t.Setenv("CADDY_CEL_FILE_TEST", "expanded-decoy.txt")
	root := t.TempDir()
	for _, name := range []string{token, "expanded-decoy.txt", "prefix" + token, "prefixexpanded-decoy.txt"} {
		if err := os.WriteFile(filepath.Join(root, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct{ name, expr, want string }{
		{"direct", `file({http.request.header.X-File})`, "/" + token},
		{"repeated", `file({http.request.header.X-File}, "/missing")`, "/" + token},
		{"map list", `file({"root": ` + strconv.Quote(root) + `, "try_files": [{http.request.header.X-File}]})`, "/" + token},
		{"concatenation", `file({"root": ` + strconv.Quote(root) + `, "try_files": ["prefix" + {http.request.header.X-File}]})`, "/prefix" + token},
		{"configured template plus provider", `file({"root": ` + strconv.Quote(root) + `, "try_files": ["\{http.vars.prefix}" + {http.request.header.X-File}]})`, "/prefix" + token},
		{"configured template", `file({"root": ` + strconv.Quote(root) + `, "try_files": ["\{env.CADDY_CEL_FILE_TEST}"]})`, "/expanded-decoy.txt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("X-File", token)
			repl := caddyhttp.NewTestReplacer(req)
			repl.Set("http.vars.root", root)
			repl.Set("http.vars.prefix", "prefix")
			matchCELFile(t, tc.expr, req)
			if got, _ := repl.Get("http.matchers.file.relative"); got != tc.want {
				t.Fatalf("selected file = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCELFileProviderRootRemainsLiteral(t *testing.T) {
	const token = "{env.CADDY_CEL_ROOT_TEST}"
	t.Setenv("CADDY_CEL_ROOT_TEST", "expanded-decoy")
	parent := t.TempDir()
	for _, name := range []string{token, "expanded-decoy"} {
		root := filepath.Join(parent, name)
		if err := os.Mkdir(root, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "target.txt"), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	root := filepath.Join(parent, token)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Root", root)
	repl := caddyhttp.NewTestReplacer(req)
	matchCELFile(t, `file({"root": {http.request.header.X-Root}, "try_files": ["target.txt"]})`, req)
	want := filepath.ToSlash(filepath.Join(root, "target.txt"))
	if got, _ := repl.Get("http.matchers.file.absolute"); got != want {
		t.Fatalf("selected file = %q, want %q", got, want)
	}
}

func TestCELFileRawPolicyAndSplitPath(t *testing.T) {
	root := t.TempDir()
	const name = "script{suffix}"
	if err := os.WriteFile(filepath.Join(root, name), nil, 0600); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-File", name+"/extra")
	req.Header.Set("X-Split", "{suffix}")
	req.Header.Set("X-Policy", "first_exist")
	repl := caddyhttp.NewTestReplacer(req)
	matchCELFile(t, `file({"root": `+strconv.Quote(root)+`, "try_files": [{http.request.header.X-File}], "split_path": [{http.request.header.X-Split}], "try_policy": {http.request.header.X-Policy}})`, req)
	if got, _ := repl.Get("http.matchers.file.relative"); got != "/"+name {
		t.Fatalf("selected file = %q, want %q", got, "/"+name)
	}
	if got, _ := repl.Get("http.matchers.file.remainder"); got != "/extra" {
		t.Fatalf("remainder = %q, want /extra", got)
	}
}

func matchCELFile(t *testing.T, expr string, req *http.Request) {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	m := caddyhttp.MatchExpression{Expr: expr}
	if err := m.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	if matched, err := m.MatchWithError(req); err != nil || !matched {
		t.Fatalf("expression %s: matched=%v, error=%v", expr, matched, err)
	}
}
