package httpcaddyfile

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	_ "github.com/caddyserver/caddy/v2/modules/logging"
)

func TestGlobalLogOptionSyntax(t *testing.T) {
	for i, tc := range []struct {
		input       string
		output      string
		expectError bool
	}{
		// NOTE: Additional test cases of successful Caddyfile parsing
		// are present in: caddytest/integration/caddyfile_adapt/
		{
			input: `{
				log default
			}
			`,
			output:      `{}`,
			expectError: false,
		},
		{
			input: `{
				log example {
					output file foo.log
				}
				log example {
					format json
				}
			}
			`,
			expectError: true,
		},
		{
			input: `{
				log example /foo {
					output file foo.log
				}
			}
			`,
			expectError: true,
		},
	} {

		adapter := caddyfile.Adapter{
			ServerType: ServerType{},
		}

		out, _, err := adapter.Adapt([]byte(tc.input), nil)

		if err != nil != tc.expectError {
			t.Errorf("Test %d error expectation failed Expected: %v, got %v", i, tc.expectError, err)
			continue
		}

		if string(out) != tc.output {
			t.Errorf("Test %d error output mismatch Expected: %s, got %s", i, tc.output, out)
		}
	}
}
