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
