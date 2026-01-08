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

//go:build !windows

package caddy

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestFastAbs(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		checkFunc func(result string, err error) error
	}{
		{
			name:  "absolute path",
			input: "/usr/local/bin",
			checkFunc: func(result string, err error) error {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
				if result != "/usr/local/bin" {
					t.Errorf("expected /usr/local/bin, got %s", result)
				}
				return nil
			},
		},
		{
			name:  "absolute path with dots",
			input: "/usr/local/../bin",
			checkFunc: func(result string, err error) error {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
				if result != "/usr/bin" {
					t.Errorf("expected /usr/bin, got %s", result)
				}
				return nil
			},
		},
		{
			name:  "relative path",
			input: "relative/path",
			checkFunc: func(result string, err error) error {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
				if !filepath.IsAbs(result) {
					t.Errorf("expected absolute path, got %s", result)
				}
				if !strings.HasSuffix(result, "relative/path") {
					t.Errorf("expected path to end with 'relative/path', got %s", result)
				}
				return nil
			},
		},
		{
			name:  "dot",
			input: ".",
			checkFunc: func(result string, err error) error {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
				if !filepath.IsAbs(result) {
					t.Errorf("expected absolute path, got %s", result)
				}
				return nil
			},
		},
		{
			name:  "dot dot",
			input: "..",
			checkFunc: func(result string, err error) error {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
				if !filepath.IsAbs(result) {
					t.Errorf("expected absolute path, got %s", result)
				}
				return nil
			},
		},
		{
			name:  "empty string",
			input: "",
			checkFunc: func(result string, err error) error {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
				// Empty string should resolve to current directory
				if !filepath.IsAbs(result) {
					t.Errorf("expected absolute path, got %s", result)
				}
				return nil
			},
		},
		{
			name:  "complex relative path",
			input: "./foo/../bar/./baz",
			checkFunc: func(result string, err error) error {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
				if !filepath.IsAbs(result) {
					t.Errorf("expected absolute path, got %s", result)
				}
				if !strings.HasSuffix(result, "bar/baz") {
					t.Errorf("expected path to end with 'bar/baz', got %s", result)
				}
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := FastAbs(tt.input)
			tt.checkFunc(result, err)
		})
	}
}

// TestFastAbsVsFilepathAbs compares FastAbs with filepath.Abs to ensure consistent behavior
func TestFastAbsVsFilepathAbs(t *testing.T) {
	// Skip if working directory cannot be determined
	if wderr != nil {
		t.Skip("working directory error, skipping comparison test")
	}

	testPaths := []string{
		".",
		"..",
		"foo",
		"foo/bar",
		"./foo",
		"../foo",
		"/absolute/path",
		"/usr/local/bin",
	}

	for _, path := range testPaths {
		t.Run(path, func(t *testing.T) {
			fast, fastErr := FastAbs(path)
			std, stdErr := filepath.Abs(path)

			// Both should succeed or fail together
			if (fastErr != nil) != (stdErr != nil) {
				t.Errorf("error mismatch: FastAbs=%v, filepath.Abs=%v", fastErr, stdErr)
			}

			// If both succeed, results should be the same
			if fastErr == nil && stdErr == nil && fast != std {
				t.Errorf("result mismatch for %q: FastAbs=%s, filepath.Abs=%s", path, fast, std)
			}
		})
	}
}

// TestFastAbsErrorHandling tests error handling when working directory is unavailable
func TestFastAbsErrorHandling(t *testing.T) {
	// This tests the cached wderr behavior
	if wderr != nil {
		// Test that FastAbs properly returns the cached error for relative paths
		_, err := FastAbs("relative/path")
		if err == nil {
			t.Error("expected error for relative path when working directory is unavailable")
		}
		if err != wderr {
			t.Errorf("expected cached wderr, got different error: %v", err)
		}
	}
}

// BenchmarkFastAbs benchmarks FastAbs
func BenchmarkFastAbs(b *testing.B) {
	paths := []string{
		"relative/path",
		"/absolute/path",
		".",
		"..",
		"./foo/bar",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		FastAbs(paths[i%len(paths)])
	}
}

// BenchmarkFastAbsVsStdLib compares performance of FastAbs vs filepath.Abs
func BenchmarkFastAbsVsStdLib(b *testing.B) {
	path := "relative/path/to/file"

	b.Run("FastAbs", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			FastAbs(path)
		}
	})

	b.Run("filepath.Abs", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			filepath.Abs(path)
		}
	})
}
