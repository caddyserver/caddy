package caddyhttp

import (
	"net/url"
	"path/filepath"
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

func TestUnmarshalRatio(t *testing.T) {
	for i, tc := range []struct {
		input  []byte
		expect float64
		errMsg string
	}{
		{
			input:  []byte("null"),
			expect: 0,
		},
		{
			input:  []byte(`"1/3"`),
			expect: float64(1) / float64(3),
		},
		{
			input:  []byte(`"1/100"`),
			expect: float64(1) / float64(100),
		},
		{
			input:  []byte(`"3:2"`),
			expect: 0.6,
		},
		{
			input:  []byte(`"99:1"`),
			expect: 0.99,
		},
		{
			input:  []byte(`"1/100"`),
			expect: float64(1) / float64(100),
		},
		{
			input:  []byte(`0.1`),
			expect: 0.1,
		},
		{
			input:  []byte(`0.005`),
			expect: 0.005,
		},
		{
			input:  []byte(`0`),
			expect: 0,
		},
		{
			input:  []byte(`"0"`),
			errMsg: `ratio string '0' did not contain a slash '/' or colon ':'`,
		},
		{
			input:  []byte(`a`),
			errMsg: `failed parsing ratio as float a: strconv.ParseFloat: parsing "a": invalid syntax`,
		},
		{
			input:  []byte(`"a/1"`),
			errMsg: `failed parsing numerator as integer a: strconv.Atoi: parsing "a": invalid syntax`,
		},
		{
			input:  []byte(`"1/a"`),
			errMsg: `failed parsing denominator as integer a: strconv.Atoi: parsing "a": invalid syntax`,
		},
	} {
		ratio := Ratio(0)
		err := ratio.UnmarshalJSON(tc.input)
		if err != nil {
			if tc.errMsg != "" {
				if tc.errMsg != err.Error() {
					t.Fatalf("Test %d: expected error: %v, got: %v", i, tc.errMsg, err)
				}
				continue
			}
			t.Fatalf("Test %d: invalid ratio: %v", i, err)
		}
		if ratio != Ratio(tc.expect) {
			t.Fatalf("Test %d: expected %v, got %v", i, tc.expect, ratio)
		}
	}
}
