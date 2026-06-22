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

package caddy

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"
)

func TestParseDuration_EdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expectErr bool
		expected  time.Duration
	}{
		{
			name:     "zero duration",
			input:    "0",
			expected: 0,
		},
		{
			name:      "invalid format",
			input:     "abc",
			expectErr: true,
		},
		{
			name:     "negative days",
			input:    "-2d",
			expected: -48 * time.Hour,
		},
		{
			name:     "decimal days",
			input:    "0.5d",
			expected: 12 * time.Hour,
		},
		{
			name:     "large decimal days",
			input:    "365.25d",
			expected: time.Duration(365.25*24) * time.Hour,
		},
		{
			name:     "multiple days in same string",
			input:    "1d2d3d",
			expected: (24 * 6) * time.Hour, // 6 days total
		},
		{
			name:     "days with other units",
			input:    "1d30m15s",
			expected: 24*time.Hour + 30*time.Minute + 15*time.Second,
		},
		{
			name:      "malformed days",
			input:     "d",
			expectErr: true,
		},
		{
			name:      "invalid day value",
			input:     "abcd",
			expectErr: true,
		},
		{
			name:      "overflow protection",
			input:     "9999999999999999999999999d",
			expectErr: true,
		},
		{
			name:     "zero days",
			input:    "0d",
			expected: 0,
		},
		{
			name:      "input at limit",
			input:     strings.Repeat("1", 1024) + "ns",
			expectErr: true, // Likely to cause parsing error due to size
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := ParseDuration(test.input)

			if test.expectErr && err == nil {
				t.Error("Expected error but got none")
			}
			if !test.expectErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if !test.expectErr && result != test.expected {
				t.Errorf("Expected %v, got %v", test.expected, result)
			}
		})
	}
}

func TestParseDuration_InputLengthLimit(t *testing.T) {
	// Test the 1024 character limit
	longInput := strings.Repeat("1", 1025) + "s"

	_, err := ParseDuration(longInput)
	if err == nil {
		t.Error("Expected error for input longer than 1024 characters")
	}

	expectedErrMsg := "parsing duration: input string too long"
	if err.Error() != expectedErrMsg {
		t.Errorf("Expected error message '%s', got '%s'", expectedErrMsg, err.Error())
	}
}

func TestParseDuration_ComplexNumberFormats(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
	}{
		{
			input:    "+1d",
			expected: 24 * time.Hour,
		},
		{
			input:    "-1.5d",
			expected: -36 * time.Hour,
		},
		{
			input:    "1.0d",
			expected: 24 * time.Hour,
		},
		{
			input:    "0.25d",
			expected: 6 * time.Hour,
		},
		{
			input:    "1.5d30m",
			expected: 36*time.Hour + 30*time.Minute,
		},
		{
			input:    "2.5d1h30m45s",
			expected: 60*time.Hour + time.Hour + 30*time.Minute + 45*time.Second,
		},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result, err := ParseDuration(test.input)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if result != test.expected {
				t.Errorf("Expected %v, got %v", test.expected, result)
			}
		})
	}
}

func TestDuration_UnmarshalJSON_TypeValidation(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expectErr bool
		expected  time.Duration
	}{
		{
			name:      "null value",
			input:     "null",
			expectErr: false,
			expected:  0,
		},
		{
			name:      "boolean value",
			input:     "true",
			expectErr: true,
		},
		{
			name:      "array value",
			input:     `[1,2,3]`,
			expectErr: true,
		},
		{
			name:      "object value",
			input:     `{"duration": "5m"}`,
			expectErr: true,
		},
		{
			name:      "negative integer",
			input:     "-1000000000",
			expected:  -time.Second,
			expectErr: false,
		},
		{
			name:      "zero integer",
			input:     "0",
			expected:  0,
			expectErr: false,
		},
		{
			name:      "large integer",
			input:     "9223372036854775807", // Max int64
			expected:  time.Duration(math.MaxInt64),
			expectErr: false,
		},
		{
			name:      "float as integer (invalid JSON for int)",
			input:     "1.5",
			expectErr: true,
		},
		{
			name:      "string with special characters",
			input:     `"5m\"30s"`,
			expectErr: true,
		},
		{
			name:      "string with unicode",
			input:     `"5m🚀"`,
			expectErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var d Duration
			err := d.UnmarshalJSON([]byte(test.input))

			if test.expectErr && err == nil {
				t.Error("Expected error but got none")
			}
			if !test.expectErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if !test.expectErr && time.Duration(d) != test.expected {
				t.Errorf("Expected %v, got %v", test.expected, time.Duration(d))
			}
		})
	}
}

func TestDuration_JSON_RoundTrip(t *testing.T) {
	tests := []struct {
		duration time.Duration
		asString bool
	}{
		{duration: 5 * time.Minute, asString: true},
		{duration: 24 * time.Hour, asString: false}, // Will be stored as nanoseconds
		{duration: 0, asString: false},
		{duration: -time.Hour, asString: true},
		{duration: time.Nanosecond, asString: false},
		{duration: time.Second, asString: false},
	}

	for _, test := range tests {
		t.Run(test.duration.String(), func(t *testing.T) {
			d := Duration(test.duration)

			// Marshal to JSON
			jsonData, err := json.Marshal(d)
			if err != nil {
				t.Fatalf("Failed to marshal: %v", err)
			}

			// Unmarshal back
			var unmarshaled Duration
			err = unmarshaled.UnmarshalJSON(jsonData)
			if err != nil {
				t.Fatalf("Failed to unmarshal: %v", err)
			}

			// Should be equal
			if time.Duration(unmarshaled) != test.duration {
				t.Errorf("Round trip failed: expected %v, got %v", test.duration, time.Duration(unmarshaled))
			}
		})
	}
}

func TestParseDuration_Precision(t *testing.T) {
	// Test floating point precision with days
	tests := []struct {
		input    string
		expected time.Duration
	}{
		{
			input:    "0.1d",
			expected: time.Duration(0.1 * 24 * float64(time.Hour)),
		},
		{
			input:    "0.01d",
			expected: time.Duration(0.01 * 24 * float64(time.Hour)),
		},
		{
			input:    "0.001d",
			expected: time.Duration(0.001 * 24 * float64(time.Hour)),
		},
		{
			input:    "1.23456789d",
			expected: time.Duration(1.23456789 * 24 * float64(time.Hour)),
		},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result, err := ParseDuration(test.input)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			// Allow for small floating point differences
			diff := result - test.expected
			if diff < 0 {
				diff = -diff
			}
			if diff > time.Nanosecond {
				t.Errorf("Expected %v, got %v (diff: %v)", test.expected, result, diff)
			}
		})
	}
}

func TestParseDuration_Boundary_Values(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expectErr bool
	}{
		{
			name:  "minimum day value",
			input: "0.000000001d", // Very small but valid
		},
		{
			name:      "very large day value",
			input:     "999999999999999999999d",
			expectErr: true, // Should overflow
		},
		{
			name:  "negative zero",
			input: "-0d",
		},
		{
			name:  "positive zero",
			input: "+0d",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseDuration(test.input)

			if test.expectErr && err == nil {
				t.Error("Expected error but got none")
			}
			if !test.expectErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func BenchmarkParseDuration_SimpleDay(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ParseDuration("1d")
	}
}

func BenchmarkParseDuration_ComplexDay(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ParseDuration("1.5d30m15.5s")
	}
}

func BenchmarkParseDuration_MultipleDays(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ParseDuration("1d2d3d4d5d")
	}
}

func BenchmarkDuration_UnmarshalJSON_String(b *testing.B) {
	input := []byte(`"5m30s"`)
	var d Duration

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.UnmarshalJSON(input)
	}
}

func BenchmarkDuration_UnmarshalJSON_Integer(b *testing.B) {
	input := []byte("300000000000") // 5 minutes in nanoseconds
	var d Duration

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.UnmarshalJSON(input)
	}
}
