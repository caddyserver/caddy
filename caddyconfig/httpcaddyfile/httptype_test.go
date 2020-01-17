package httpcaddyfile

import "testing"

func TestSpecificity(t *testing.T) {
	for i, tc := range []struct {
		input  string
		expect int
	}{
		{"", 0},
		{"*", 0},
		{"*.*", 1},
		{"{placeholder}", 0},
		{"/{placeholder}", 1},
		{"foo", 3},
		{"example.com", 11},
		{"a.example.com", 13},
		{"*.example.com", 12},
		{"/foo", 4},
		{"/foo*", 4},
		{"{placeholder}.example.com", 12},
		{"{placeholder.example.com", 24},
		{"}.", 2},
		{"}{", 2},
		{"{}", 0},
		{"{{{}}", 1},
	} {
		actual := specificity(tc.input)
		if actual != tc.expect {
			t.Errorf("Test %d (%s): Expected %d but got %d", i, tc.input, tc.expect, actual)
		}
	}
}
