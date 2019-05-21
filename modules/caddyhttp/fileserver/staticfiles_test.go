package fileserver

import (
	"net/url"
	"testing"
)

func TestSanitizedPathJoin(t *testing.T) {
	// For easy reference:
	// %2E = .
	// %2F = /
	// %5C = \
	for i, tc := range []struct {
		inputRoot string
		inputPath string
		expect    string
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
			inputPath: "/foo/bar",
			expect:    "foo/bar",
		},
		{
			inputRoot: "/a",
			inputPath: "/foo/bar",
			expect:    "/a/foo/bar",
		},
		{
			inputPath: "/foo/../bar",
			expect:    "bar",
		},
		{
			inputRoot: "/a/b",
			inputPath: "/foo/../bar",
			expect:    "/a/b/bar",
		},
		{
			inputRoot: "/a/b",
			inputPath: "/..%2fbar",
			expect:    "/a/b/bar",
		},
		{
			inputRoot: "/a/b",
			inputPath: "/%2e%2e%2fbar",
			expect:    "/a/b/bar",
		},
		{
			inputRoot: "/a/b",
			inputPath: "/%2e%2e%2f%2e%2e%2f",
			expect:    "/a/b",
		},
		// TODO: test windows paths... on windows... sigh.
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
		actual := sanitizedPathJoin(tc.inputRoot, u.Path)
		if actual != tc.expect {
			t.Errorf("Test %d: [%s %s] => %s (expected %s)", i, tc.inputRoot, tc.inputPath, actual, tc.expect)
		}
	}
}

// TODO: test fileHidden
