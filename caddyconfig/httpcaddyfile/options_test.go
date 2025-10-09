package httpcaddyfile

import (
	"encoding/json"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
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

func TestGlobalResolversOption(t *testing.T) {
	tests := []struct {
		name            string
		input           string
		expectResolvers []string
		expectError     bool
	}{
		{
			name: "single resolver",
			input: `{
				resolvers 1.1.1.1
			}
			example.com {
			}`,
			expectResolvers: []string{"1.1.1.1"},
			expectError:     false,
		},
		{
			name: "two resolvers",
			input: `{
				resolvers 1.1.1.1 8.8.8.8
			}
			example.com {
			}`,
			expectResolvers: []string{"1.1.1.1", "8.8.8.8"},
			expectError:     false,
		},
		{
			name: "multiple resolvers",
			input: `{
				resolvers 1.1.1.1 8.8.8.8 9.9.9.9
			}
			example.com {
			}`,
			expectResolvers: []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"},
			expectError:     false,
		},
		{
			name: "no resolvers specified",
			input: `{
			}
			example.com {
			}`,
			expectResolvers: nil,
			expectError:     false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			adapter := caddyfile.Adapter{
				ServerType: ServerType{},
			}

			out, _, err := adapter.Adapt([]byte(tc.input), nil)

			if (err != nil) != tc.expectError {
				t.Errorf("error expectation failed. Expected error: %v, got: %v", tc.expectError, err)
				return
			}

			if tc.expectError {
				return
			}

			// Parse the output JSON to check resolvers
			var config struct {
				Apps struct {
					TLS *caddytls.TLS `json:"tls"`
				} `json:"apps"`
			}

			if err := json.Unmarshal(out, &config); err != nil {
				t.Errorf("failed to unmarshal output: %v", err)
				return
			}

			// Check if resolvers match expected
			if config.Apps.TLS == nil {
				if tc.expectResolvers != nil {
					t.Errorf("Expected TLS config with resolvers %v, but TLS config is nil", tc.expectResolvers)
				}
				return
			}

			actualResolvers := config.Apps.TLS.Resolvers
			if len(tc.expectResolvers) == 0 && len(actualResolvers) == 0 {
				return // Both empty, ok
			}
			if len(actualResolvers) != len(tc.expectResolvers) {
				t.Errorf("Expected %d resolvers, got %d. Expected: %v, got: %v", len(tc.expectResolvers), len(actualResolvers), tc.expectResolvers, actualResolvers)
				return
			}
			for j, expected := range tc.expectResolvers {
				if actualResolvers[j] != expected {
					t.Errorf("Resolver %d mismatch. Expected: %s, got: %s", j, expected, actualResolvers[j])
				}
			}
		})
	}
}
