package httpcaddyfile

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	_ "github.com/caddyserver/caddy/v2/modules/logging"
)

func TestLogDirectiveSyntax(t *testing.T) {
	for i, tc := range []struct {
		input       string
		expectError bool
	}{
		{
			input: `:8080 {
				log
			}
			`,
			expectError: false,
		},
		{
			input: `:8080 {
				log {
					output file foo.log
				}
			}
			`,
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
			expectError: false,
		},
		{
			input: `:8080 {
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

		_, _, err := adapter.Adapt([]byte(tc.input), nil)

		if err != nil != tc.expectError {
			t.Errorf("Test %d error expectation failed Expected: %v, got %s", i, tc.expectError, err)
			continue
		}
	}
}
