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

package rewrite

import (
	"testing"
)

func TestReverse(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple string",
			input:    "hello",
			expected: "olleh",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "single character",
			input:    "a",
			expected: "a",
		},
		{
			name:     "two characters",
			input:    "ab",
			expected: "ba",
		},
		{
			name:     "palindrome",
			input:    "racecar",
			expected: "racecar",
		},
		{
			name:     "with spaces",
			input:    "hello world",
			expected: "dlrow olleh",
		},
		{
			name:     "with numbers",
			input:    "abc123",
			expected: "321cba",
		},
		{
			name:     "unicode characters",
			input:    "hello世界",
			expected: "界世olleh",
		},
		{
			name:     "emoji",
			input:    "🎉🎊🎈",
			expected: "🎈🎊🎉",
		},
		{
			name:     "mixed unicode and ascii",
			input:    "café☕",
			expected: "☕éfac",
		},
		{
			name:     "special characters",
			input:    "a!b@c#d$",
			expected: "$d#c@b!a",
		},
		{
			name:     "path-like string",
			input:    "/path/to/file",
			expected: "elif/ot/htap/",
		},
		{
			name:     "url-like string",
			input:    "https://example.com",
			expected: "moc.elpmaxe//:sptth",
		},
		{
			name:     "long string",
			input:    "The quick brown fox jumps over the lazy dog",
			expected: "god yzal eht revo spmuj xof nworb kciuq ehT",
		},
		{
			name:     "newlines",
			input:    "line1\nline2\nline3",
			expected: "3enil\n2enil\n1enil",
		},
		{
			name:     "tabs",
			input:    "a\tb\tc",
			expected: "c\tb\ta",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := reverse(tt.input)
			if result != tt.expected {
				t.Errorf("reverse(%q) = %q; want %q", tt.input, result, tt.expected)
			}

			// Test that reversing twice gives the original string
			if tt.input != "" {
				doubleReverse := reverse(reverse(tt.input))
				if doubleReverse != tt.input {
					t.Errorf("reverse(reverse(%q)) = %q; want %q", tt.input, doubleReverse, tt.input)
				}
			}
		})
	}
}

func TestReverse_LengthPreservation(t *testing.T) {
	// Test that reverse preserves string length
	testStrings := []string{
		"",
		"a",
		"ab",
		"abc",
		"hello world",
		"🎉🎊🎈",
		"café☕",
		"The quick brown fox jumps over the lazy dog",
	}

	for _, s := range testStrings {
		reversed := reverse(s)
		if len([]rune(s)) != len([]rune(reversed)) {
			t.Errorf("reverse(%q) changed length: original %d, reversed %d", s, len([]rune(s)), len([]rune(reversed)))
		}
	}
}

// BenchmarkReverse benchmarks the reverse function
func BenchmarkReverse(b *testing.B) {
	testCases := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"short", "hello"},
		{"medium", "The quick brown fox jumps over the lazy dog"},
		{"long", "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."},
		{"unicode", "hello世界🎉"},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				reverse(tc.input)
			}
		})
	}
}

func TestReverse_EdgeCases(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"null byte", "\x00"},
		{"multiple null bytes", "\x00\x00\x00"},
		{"control characters", "\t\n\r"},
		{"high unicode", "𝕳𝖊𝖑𝖑𝖔"},
		{"zero-width characters", "a\u200Bb\u200Cc"},
		{"combining characters", "é"}, // e + combining acute
		{"rtl text", "مرحبا"},
		{"mixed rtl/ltr", "Hello مرحبا World"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := reverse(tt.input)
			// Just ensure it doesn't panic and returns something
			if result == "" && tt.input != "" {
				t.Errorf("reverse(%q) returned empty string", tt.input)
			}
		})
	}
}
