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
		statusCode int
		want       string
	}{
		{
			statusCode: 200,
			want:       "200",
		},
		{
			statusCode: 400,
			want:       "400",
		},
		{
			statusCode: 500,
			want:       "500",
		},
	}
	for _, test := range tests {
		got := SanitizeCode(test.statusCode)
		if got != test.want {
			t.Errorf("Not same: expected %#v, but got %#v", test.want, got)
		}
	}
}
