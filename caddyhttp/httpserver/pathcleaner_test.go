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

func assertEqual(t *testing.T, expected, received string) {
	if expected != received {
		t.Errorf("\tExpected: %s\n\t\t\tReceived: %s", expected, received)
	}
}

func maskedTestRunner(t *testing.T, variation string, masks ...string) {
	for reqPath, transformation := range paths {
		assertEqual(t, transformation[variation], CleanMaskedPath(reqPath, masks...))
	}
}

// No need to test the built-in path.Clean() function.
// However, it could be useful to cross-examine the test dataset.
func TestPathClean(t *testing.T) {
	for reqPath, transformation := range paths {
		assertEqual(t, transformation["clean_all"], path.Clean(reqPath))
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
	for reqPath, transformation := range paths {
		assertEqual(t, transformation["preserve_protocol"], CleanPath(reqPath))
	}
}

func maskedBenchmarkRunner(b *testing.B, masks ...string) {
	for n := 0; n < b.N; n++ {
		for reqPath := range paths {
			CleanMaskedPath(reqPath, masks...)
		}
	}
}

func BenchmarkPathClean(b *testing.B) {
	for n := 0; n < b.N; n++ {
		for reqPath := range paths {
			path.Clean(reqPath)
		}
	}
}

func BenchmarkCleanAll(b *testing.B) {
	maskedBenchmarkRunner(b)
}

func BenchmarkPreserveAll(b *testing.B) {
	maskedBenchmarkRunner(b, "//", "/..", "/.")
}

func BenchmarkPreserveProtocol(b *testing.B) {
	maskedBenchmarkRunner(b, "://")
}

func BenchmarkPreserveSlashes(b *testing.B) {
	maskedBenchmarkRunner(b, "//")
}

func BenchmarkPreserveDots(b *testing.B) {
	maskedBenchmarkRunner(b, "/..", "/.")
}

func BenchmarkDefaultMask(b *testing.B) {
	for n := 0; n < b.N; n++ {
		for reqPath := range paths {
			CleanPath(reqPath)
		}
	}
}
