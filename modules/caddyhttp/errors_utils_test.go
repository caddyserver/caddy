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

package caddyhttp

import (
	"strings"
	"testing"
	"unicode"
)

func TestRandString(t *testing.T) {
	tests := []struct {
		name      string
		length    int
		sameCase  bool
		wantLen   int
		checkCase func(string) bool
	}{
		{
			name:     "zero length",
			length:   0,
			sameCase: false,
			wantLen:  0,
			checkCase: func(s string) bool {
				return s == ""
			},
		},
		{
			name:     "negative length",
			length:   -5,
			sameCase: false,
			wantLen:  0,
			checkCase: func(s string) bool {
				return s == ""
			},
		},
		{
			name:     "single character mixed case",
			length:   1,
			sameCase: false,
			wantLen:  1,
			checkCase: func(s string) bool {
				// Should be alphanumeric
				return len(s) == 1 && (unicode.IsLetter(rune(s[0])) || unicode.IsDigit(rune(s[0])))
			},
		},
		{
			name:     "single character same case",
			length:   1,
			sameCase: true,
			wantLen:  1,
			checkCase: func(s string) bool {
				// Should be lowercase or digit
				return len(s) == 1 && (unicode.IsLower(rune(s[0])) || unicode.IsDigit(rune(s[0])))
			},
		},
		{
			name:     "short string mixed case",
			length:   5,
			sameCase: false,
			wantLen:  5,
			checkCase: func(s string) bool {
				// All characters should be alphanumeric
				for _, c := range s {
					if !unicode.IsLetter(c) && !unicode.IsDigit(c) {
						return false
					}
				}
				return true
			},
		},
		{
			name:     "short string same case",
			length:   5,
			sameCase: true,
			wantLen:  5,
			checkCase: func(s string) bool {
				// All characters should be lowercase or digits
				for _, c := range s {
					if unicode.IsUpper(c) {
						return false
					}
					if !unicode.IsLetter(c) && !unicode.IsDigit(c) {
						return false
					}
				}
				return true
			},
		},
		{
			name:     "medium string mixed case",
			length:   20,
			sameCase: false,
			wantLen:  20,
			checkCase: func(s string) bool {
				for _, c := range s {
					if !unicode.IsLetter(c) && !unicode.IsDigit(c) {
						return false
					}
				}
				return true
			},
		},
		{
			name:     "long string same case",
			length:   100,
			sameCase: true,
			wantLen:  100,
			checkCase: func(s string) bool {
				for _, c := range s {
					if unicode.IsUpper(c) {
						return false
					}
				}
				return true
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := randString(tt.length, tt.sameCase)

			// Check length
			if len(result) != tt.wantLen {
				t.Errorf("randString(%d, %v) length = %d, want %d",
					tt.length, tt.sameCase, len(result), tt.wantLen)
			}

			// Check case requirements
			if !tt.checkCase(result) {
				t.Errorf("randString(%d, %v) = %q failed case check",
					tt.length, tt.sameCase, result)
			}
		})
	}
}

// TestRandString_NoConfusingChars ensures that confusing characters
// like I, l, 1, 0, O are excluded from the generated strings
func TestRandString_NoConfusingChars(t *testing.T) {
	tests := []struct {
		name     string
		sameCase bool
		excluded []rune
	}{
		{
			name:     "mixed case excludes I,l,1,0,O",
			sameCase: false,
			excluded: []rune{'I', 'l', '1', '0', 'O'},
		},
		{
			name:     "same case excludes l,0",
			sameCase: true,
			excluded: []rune{'l', 'o'},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate multiple strings to increase confidence
			for i := 0; i < 100; i++ {
				result := randString(50, tt.sameCase)

				for _, char := range tt.excluded {
					if strings.ContainsRune(result, char) {
						t.Errorf("randString(50, %v) contains excluded character %q in %q",
							tt.sameCase, char, result)
					}
				}
			}
		})
	}
}

// TestRandString_Uniqueness verifies that consecutive calls produce
// different strings (with high probability)
func TestRandString_Uniqueness(t *testing.T) {
	const iterations = 100
	const length = 16

	tests := []struct {
		name     string
		sameCase bool
	}{
		{"mixed case", false},
		{"same case", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seen := make(map[string]bool)
			duplicates := 0

			for i := 0; i < iterations; i++ {
				result := randString(length, tt.sameCase)
				if seen[result] {
					duplicates++
				}
				seen[result] = true
			}

			// With a 16-character string from a large alphabet, duplicates should be extremely rare
			// Allow at most 1 duplicate in 100 iterations
			if duplicates > 1 {
				t.Errorf("randString(%d, %v) produced %d duplicates in %d iterations (expected ≤1)",
					length, tt.sameCase, duplicates, iterations)
			}
		})
	}
}

// TestRandString_CharacterDistribution checks that the generated strings
// contain a reasonable mix of characters (not just one character)
func TestRandString_CharacterDistribution(t *testing.T) {
	const length = 1000
	const minUniqueChars = 15 // Should have at least 15 different characters in 1000 chars

	tests := []struct {
		name     string
		sameCase bool
	}{
		{"mixed case", false},
		{"same case", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := randString(length, tt.sameCase)

			uniqueChars := make(map[rune]bool)
			for _, c := range result {
				uniqueChars[c] = true
			}

			if len(uniqueChars) < minUniqueChars {
				t.Errorf("randString(%d, %v) produced only %d unique characters (expected ≥%d)",
					length, tt.sameCase, len(uniqueChars), minUniqueChars)
			}
		})
	}
}

// BenchmarkRandString measures the performance of random string generation
func BenchmarkRandString(b *testing.B) {
	benchmarks := []struct {
		name     string
		length   int
		sameCase bool
	}{
		{"short_mixed", 8, false},
		{"short_same", 8, true},
		{"medium_mixed", 32, false},
		{"medium_same", 32, true},
		{"long_mixed", 128, false},
		{"long_same", 128, true},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = randString(bm.length, bm.sameCase)
			}
		})
	}
}
