package httpserver

import (
	"path"
	"testing"
)

var paths = map[string]map[string]string{
	"/../a/b/../././/c": {
		"preserve_all":      "/../a/b/../././/c",
		"preserve_protocol": "/a/c",
		"preserve_slashes":  "/a//c",
		"preserve_dots":     "/../a/b/../././c",
		"clean_all":         "/a/c",
	},
	"/path/https://www.google.com": {
		"preserve_all":      "/path/https://www.google.com",
		"preserve_protocol": "/path/https://www.google.com",
		"preserve_slashes":  "/path/https://www.google.com",
		"preserve_dots":     "/path/https:/www.google.com",
		"clean_all":         "/path/https:/www.google.com",
	},
	"/a/b/../././/c/http://example.com/foo//bar/../blah": {
		"preserve_all":      "/a/b/../././/c/http://example.com/foo//bar/../blah",
		"preserve_protocol": "/a/c/http://example.com/foo/blah",
		"preserve_slashes":  "/a//c/http://example.com/foo/blah",
		"preserve_dots":     "/a/b/../././c/http:/example.com/foo/bar/../blah",
		"clean_all":         "/a/c/http:/example.com/foo/blah",
	},
}

func assertEqual(t *testing.T, exp, rcv string) {
	if exp != rcv {
		t.Errorf("\tExpected: %s\n\t\t\tRecieved: %s", exp, rcv)
	}
}

func maskedTestRunner(t *testing.T, variation string, mask ...string) {
	for p, v := range paths {
		assertEqual(t, v[variation], CleanMaskedPath(p, mask...))
	}
}

// No need to test the built-in `path.Clean()` function.
// However, it is useful to cross-examine the test dataset.
func TestPathClean(t *testing.T) {
	for p, v := range paths {
		assertEqual(t, v["clean_all"], path.Clean(p))
	}
}

func TestCleanAll(t *testing.T) {
	maskedTestRunner(t, "clean_all")
}

func TestPreserveAll(t *testing.T) {
	maskedTestRunner(t, "preserve_all", "//", "/..", "/.")
}

func TestPreserveProtocol(t *testing.T) {
	maskedTestRunner(t, "preserve_protocol", "://")
}

func TestPreserveSlashes(t *testing.T) {
	maskedTestRunner(t, "preserve_slashes", "//")
}

func TestPreserveDots(t *testing.T) {
	maskedTestRunner(t, "preserve_dots", "/..", "/.")
}

func TestDefaultMask(t *testing.T) {
	for p, v := range paths {
		assertEqual(t, v["preserve_protocol"], CleanPath(p))
	}
}
