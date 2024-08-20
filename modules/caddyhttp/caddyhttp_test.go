package caddyhttp

import (
	"net/url"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSanitizedPathJoin(t *testing.T) {
	// For reference:
	// %2e = .
	// %2f = /
	// %5c = \
	for i, tc := range []struct {
		inputRoot     string
		inputPath     string
		expect        string
		expectWindows string
	}{
		{
			inputPath: "",
			expect:    ".",
		},
		{
			inputPath: "/",
			expect:    ".",
		},
		{
			// fileserver.MatchFile passes an inputPath of "//" for some try_files values.
			// See https://github.com/caddyserver/caddy/issues/6352
			inputPath: "//",
			expect:    filepath.FromSlash("./"),
		},
		{
			inputPath: "/foo",
			expect:    "foo",
		},
		{
			inputPath: "/foo/",
			expect:    filepath.FromSlash("foo/"),
		},
		{
			inputPath: "/foo/bar",
			expect:    filepath.FromSlash("foo/bar"),
		},
		{
			inputRoot: "/a",
			inputPath: "/foo/bar",
			expect:    filepath.FromSlash("/a/foo/bar"),
		},
		{
			inputPath: "/foo/../bar",
			expect:    "bar",
		},
		{
			inputRoot: "/a/b",
			inputPath: "/foo/../bar",
			expect:    filepath.FromSlash("/a/b/bar"),
		},
		{
			inputRoot: "/a/b",
			inputPath: "/..%2fbar",
			expect:    filepath.FromSlash("/a/b/bar"),
		},
		{
			inputRoot: "/a/b",
			inputPath: "/%2e%2e%2fbar",
			expect:    filepath.FromSlash("/a/b/bar"),
		},
		{
			// inputPath fails the IsLocal test so only the root is returned,
			// but with a trailing slash since one was included in inputPath
			inputRoot: "/a/b",
			inputPath: "/%2e%2e%2f%2e%2e%2f",
			expect:    filepath.FromSlash("/a/b/"),
		},
		{
			inputRoot: "/a/b",
			inputPath: "/foo%2fbar",
			expect:    filepath.FromSlash("/a/b/foo/bar"),
		},
		{
			inputRoot: "/a/b",
			inputPath: "/foo%252fbar",
			expect:    filepath.FromSlash("/a/b/foo%2fbar"),
		},
		{
			inputRoot: "C:\\www",
			inputPath: "/foo/bar",
			expect:    filepath.Join("C:\\www", "foo", "bar"),
		},
		{
			inputRoot:     "C:\\www",
			inputPath:     "/D:\\foo\\bar",
			expect:        filepath.Join("C:\\www", "D:\\foo\\bar"),
			expectWindows: "C:\\www", // inputPath fails IsLocal on Windows
		},
		{
			inputRoot:     `C:\www`,
			inputPath:     `/..\windows\win.ini`,
			expect:        `C:\www/..\windows\win.ini`,
			expectWindows: `C:\www`,
		},
		{
			inputRoot:     `C:\www`,
			inputPath:     `/..\..\..\..\..\..\..\..\..\..\windows\win.ini`,
			expect:        `C:\www/..\..\..\..\..\..\..\..\..\..\windows\win.ini`,
			expectWindows: `C:\www`,
		},
		{
			inputRoot:     `C:\www`,
			inputPath:     `/..%5cwindows%5cwin.ini`,
			expect:        `C:\www/..\windows\win.ini`,
			expectWindows: `C:\www`,
		},
		{
			inputRoot:     `C:\www`,
			inputPath:     `/..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini`,
			expect:        `C:\www/..\..\..\..\..\..\..\..\..\..\windows\win.ini`,
			expectWindows: `C:\www`,
		},
		{
			// https://github.com/golang/go/issues/56336#issuecomment-1416214885
			inputRoot: "root",
			inputPath: "/a/b/../../c",
			expect:    filepath.FromSlash("root/c"),
		},
	} {
		// we don't *need* to use an actual parsed URL, but it
		// adds some authenticity to the tests since real-world
		// values will be coming in from URLs; thus, the test
		// corpus can contain paths as encoded by clients, which
		// more closely emulates the actual attack vector
		u, err := url.Parse("http://test:9999" + tc.inputPath)
		if err != nil {
			t.Fatalf("Test %d: invalid URL: %v", i, err)
		}
		actual := SanitizedPathJoin(tc.inputRoot, u.Path)
		if runtime.GOOS == "windows" && tc.expectWindows != "" {
			tc.expect = tc.expectWindows
		}
		if actual != tc.expect {
			t.Errorf("Test %d: SanitizedPathJoin('%s', '%s') =>  '%s' (expected '%s')",
				i, tc.inputRoot, tc.inputPath, actual, tc.expect)
		}
	}
}

func TestCleanPath(t *testing.T) {
	for i, tc := range []struct {
		input        string
		mergeSlashes bool
		expect       string
	}{
		{
			input:  "/foo",
			expect: "/foo",
		},
		{
			input:  "/foo/",
			expect: "/foo/",
		},
		{
			input:  "//foo",
			expect: "//foo",
		},
		{
			input:        "//foo",
			mergeSlashes: true,
			expect:       "/foo",
		},
		{
			input:        "/foo//bar/",
			mergeSlashes: true,
			expect:       "/foo/bar/",
		},
		{
			input:  "/foo/./.././bar",
			expect: "/bar",
		},
		{
			input:  "/foo//./..//./bar",
			expect: "/foo//bar",
		},
		{
			input:  "/foo///./..//./bar",
			expect: "/foo///bar",
		},
		{
			input:  "/foo///./..//.",
			expect: "/foo//",
		},
		{
			input:  "/foo//./bar",
			expect: "/foo//bar",
		},
	} {
		actual := CleanPath(tc.input, tc.mergeSlashes)
		if actual != tc.expect {
			t.Errorf("Test %d [input='%s' mergeSlashes=%t]: Got '%s', expected '%s'",
				i, tc.input, tc.mergeSlashes, actual, tc.expect)
		}
	}
}
