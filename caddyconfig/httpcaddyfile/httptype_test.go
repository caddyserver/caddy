package httpcaddyfile

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestServerType(t *testing.T) {
	for i, tc := range []struct {
		input       string
		expectWarn  bool
		expectError bool
	}{
		{
			input: `http://localhost
			@debug {
			  query showdebug=1
			}
			`,
			expectWarn:  false,
			expectError: false,
		},
		{
			input: `http://localhost
			@debug {
			  query bad format
			}
			`,
			expectWarn:  false,
			expectError: true,
		},
	} {

		adapter := caddyfile.Adapter{
			ServerType: ServerType{},
		}

		_, warnings, err := adapter.Adapt([]byte(tc.input), nil)

		if len(warnings) > 0 != tc.expectWarn {
			t.Errorf("Test %d warning expectation failed Expected: %v, got %v", i, tc.expectWarn, warnings)
			continue
		}

		if err != nil != tc.expectError {
			t.Errorf("Test %d error expectation failed Expected: %v, got %s", i, tc.expectError, err)
			continue
		}
	}
}

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
