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
		inputRoot string
		inputPath string
		expect    string
		expectWin string
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
			inputPath: "/foo",
			expect:    "foo",
		},
		{
			inputPath: "/foo/",
			expect:    "foo" + separator,
		},
		{
			inputPath: "/foo/bar",
			expect:    filepath.Join("foo", "bar"),
		},
		{
			inputRoot: "/a",
			inputPath: "/foo/bar",
			expect:    filepath.Join("/", "a", "foo", "bar"),
		},
		{
			inputPath: "/foo/../bar",
			expect:    "bar",
		},
		{
			inputRoot: "/a/b",
			inputPath: "/foo/../bar",
			expect:    filepath.Join("/", "a", "b", "bar"),
		},
		{
			inputRoot: "/a/b",
			inputPath: "/..%2fbar",
			expect:    filepath.Join("/", "a", "b", "bar"),
		},
		{
			inputRoot: "/a/b",
			inputPath: "/%2e%2e%2fbar",
			expect:    filepath.Join("/", "a", "b", "bar"),
		},
		{
			inputRoot: "/a/b",
			inputPath: "/%2e%2e%2f%2e%2e%2f",
			expect:    filepath.Join("/", "a", "b") + separator,
		},
		{
			inputRoot: "C:\\www",
			inputPath: "/foo/bar",
			expect:    filepath.Join("C:\\www", "foo", "bar"),
		},
		{
			inputRoot: "C:\\www",
			inputPath: "/D:\\foo\\bar",
			expect:    filepath.Join("C:\\www", "D:\\foo\\bar"),
		},
		{
			inputRoot: "C:\\www",
			inputPath: "/file.txt . ..",
			expect:    "C:\\www/file.txt . ..",
			expectWin: "C:\\www\\file.txt",
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
		if runtime.GOOS == "windows" && tc.expectWin != "" && actual != tc.expectWin {
			t.Errorf("Test %d: SanitizedPathJoin('%s', '%s') =>  '%s' (expected '%s')",
				i, tc.inputRoot, tc.inputPath, actual, tc.expectWin)
		} else if actual != tc.expect {
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
