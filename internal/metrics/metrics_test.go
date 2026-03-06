package metrics

import (
	"strings"
	"testing"
)

func TestSanitizeMethod(t *testing.T) {
	tests := []struct {
		method   string
		expected string
	}{
		{method: "get", expected: "GET"},
		{method: "POST", expected: "POST"},
		{method: "OPTIONS", expected: "OPTIONS"},
		{method: "connect", expected: "CONNECT"},
		{method: "trace", expected: "TRACE"},
		{method: "UNKNOWN", expected: "OTHER"},
		{method: strings.Repeat("ohno", 9999), expected: "OTHER"},

		// Test all standard HTTP methods in uppercase
		{method: "GET", expected: "GET"},
		{method: "HEAD", expected: "HEAD"},
		{method: "POST", expected: "POST"},
		{method: "PUT", expected: "PUT"},
		{method: "DELETE", expected: "DELETE"},
		{method: "CONNECT", expected: "CONNECT"},
		{method: "OPTIONS", expected: "OPTIONS"},
		{method: "TRACE", expected: "TRACE"},
		{method: "PATCH", expected: "PATCH"},

		// Test all standard HTTP methods in lowercase
		{method: "get", expected: "GET"},
		{method: "head", expected: "HEAD"},
		{method: "post", expected: "POST"},
		{method: "put", expected: "PUT"},
		{method: "delete", expected: "DELETE"},
		{method: "connect", expected: "CONNECT"},
		{method: "options", expected: "OPTIONS"},
		{method: "trace", expected: "TRACE"},
		{method: "patch", expected: "PATCH"},

		// Test mixed case and non-standard methods
		{method: "Get", expected: "OTHER"},
		{method: "gEt", expected: "OTHER"},
		{method: "UNKNOWN", expected: "OTHER"},
		{method: "PROPFIND", expected: "OTHER"},
		{method: "MKCOL", expected: "OTHER"},
		{method: "", expected: "OTHER"},
		{method: " ", expected: "OTHER"},
	}

	for _, d := range tests {
		actual := SanitizeMethod(d.method)
		if actual != d.expected {
			t.Errorf("Not same: expected %#v, but got %#v", d.expected, actual)
		}
	}
}

func TestSanitizeCode(t *testing.T) {
	tests := []struct {
		name     string
		code     int
		expected string
	}{
		{
			name:     "zero returns 200",
			code:     0,
			expected: "200",
		},
		{
			name:     "200 returns 200",
			code:     200,
			expected: "200",
		},
		{
			name:     "404 returns 404",
			code:     404,
			expected: "404",
		},
		{
			name:     "500 returns 500",
			code:     500,
			expected: "500",
		},
		{
			name:     "301 returns 301",
			code:     301,
			expected: "301",
		},
		{
			name:     "418 teapot returns 418",
			code:     418,
			expected: "418",
		},
		{
			name:     "999 custom code",
			code:     999,
			expected: "999",
		},
		{
			name:     "negative code",
			code:     -1,
			expected: "-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeCode(tt.code)
			if result != tt.expected {
				t.Errorf("SanitizeCode(%d) = %s; want %s", tt.code, result, tt.expected)
			}
		})
	}
}

// BenchmarkSanitizeCode benchmarks the SanitizeCode function
func BenchmarkSanitizeCode(b *testing.B) {
	codes := []int{0, 200, 404, 500, 301, 418}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SanitizeCode(codes[i%len(codes)])
	}
}

// BenchmarkSanitizeMethod benchmarks the SanitizeMethod function
func BenchmarkSanitizeMethod(b *testing.B) {
	methods := []string{"GET", "POST", "PUT", "DELETE", "UNKNOWN"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SanitizeMethod(methods[i%len(methods)])
	}
}
