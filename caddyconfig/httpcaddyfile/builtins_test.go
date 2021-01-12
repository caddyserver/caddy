package httpcaddyfile

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	_ "github.com/caddyserver/caddy/v2/modules/logging"
)

func TestLogDirectiveSyntax(t *testing.T) {
	for i, tc := range []struct {
		input       string
		expectWarn  bool
		expectError bool
	}{
		{
			input: `:8080 {
				log
			}
			`,
			expectWarn:  false,
			expectError: false,
		},
		{
			input: `:8080 {
				log {
					output file foo.log
				}
			}
			`,
			expectWarn:  false,
			expectError: false,
		},
		{
			input: `:8080 {
				log {
					format filter {
						wrap console
						fields {
							common_log delete
							request>remote_addr ip_mask {
								ipv4 24
								ipv6 32
							}
						}
					}
				}
			}
			`,
			expectWarn:  false,
			expectError: false,
		},
		{
			input: `:8080 {
				log {
					output file foo.log
				}
				log default {
					format json
				}
			}
			`,
			expectWarn:  false,
			expectError: false,
		},
		{
			input: `:8080 {
				log example /foo {
					output file foo.log
				}
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
