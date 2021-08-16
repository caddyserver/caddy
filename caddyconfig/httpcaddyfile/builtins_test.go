package httpcaddyfile

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	_ "github.com/caddyserver/caddy/v2/modules/logging"
)

func TestLogDirectiveSyntax(t *testing.T) {
	for i, tc := range []struct {
		input       string
		output      string
		expectError bool
	}{
		{
			input: `:8080 {
				log
			}
			`,
			output:      `{"apps":{"http":{"servers":{"srv0":{"listen":[":8080"],"logs":{}}}}}}`,
			expectError: false,
		},
		{
			input: `:8080 {
				log {
					output file foo.log
				}
			}
			`,
			output:      `{"logging":{"logs":{"default":{"exclude":["http.log.access.log0"]},"log0":{"writer":{"filename":"foo.log","output":"file"},"include":["http.log.access.log0"]}}},"apps":{"http":{"servers":{"srv0":{"listen":[":8080"],"logs":{"default_logger_name":"log0"}}}}}}`,
			expectError: false,
		},
		{
			input: `:8080 {
				log {
					format filter {
						wrap console
						fields {
							request>remote_addr ip_mask {
								ipv4 24
								ipv6 32
							}
						}
					}
				}
			}
			`,
			output:      `{"logging":{"logs":{"default":{"exclude":["http.log.access.log0"]},"log0":{"encoder":{"fields":"request\u003eremote_addr":{"filter":"ip_mask","ipv4_cidr":24,"ipv6_cidr":32}},"format":"filter","wrap":{"format":"console"}},"include":["http.log.access.log0"]}}},"apps":{"http":{"servers":{"srv0":{"listen":[":8080"],"logs":{"default_logger_name":"log0"}}}}}}`,
			expectError: false,
		},
		{
			input: `:8080 {
				log invalid {
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
			t.Errorf("Test %d error expectation failed Expected: %v, got %s", i, tc.expectError, err)
			continue
		}

		if string(out) != tc.output {
			t.Errorf("Test %d error output mismatch Expected: %s, got %s", i, tc.output, out)
		}
	}
}

func TestRedirDirectiveSyntax(t *testing.T) {
	for i, tc := range []struct {
		input       string
		expectError bool
	}{
		{
			input: `:8080 {
				redir :8081
			}`,
			expectError: false,
		},
		{
			input: `:8080 {
				redir * :8081
			}`,
			expectError: false,
		},
		{
			input: `:8080 {
				redir /api/* :8081 300
			}`,
			expectError: false,
		},
		{
			input: `:8080 {
				redir :8081 300
			}`,
			expectError: false,
		},
		{
			input: `:8080 {
				redir /api/* :8081 399
			}`,
			expectError: false,
		},
		{
			input: `:8080 {
				redir :8081 399
			}`,
			expectError: false,
		},
		{
			input: `:8080 {
				redir /old.html /new.html
			}`,
			expectError: false,
		},
		{
			input: `:8080 {
				redir /old.html /new.html temporary
			}`,
			expectError: false,
		},
		{
			input: `:8080 {
				redir https://example.com{uri} permanent
			}`,
			expectError: false,
		},
		{
			input: `:8080 {
				redir /old.html /new.html permanent
			}`,
			expectError: false,
		},
		{
			input: `:8080 {
				redir /old.html /new.html html
			}`,
			expectError: false,
		},
		{
			input: `:8080 {
				redir /old.html /new.html htlm
			}`,
			expectError: true,
		},
		{
			input: `:8080 {
				redir * :8081 200
			}`,
			expectError: true,
		},
		{
			input: `:8080 {
				redir * :8081 400
			}`,
			expectError: true,
		},
		{
			input: `:8080 {
				redir * :8081 temp
			}`,
			expectError: true,
		},
		{
			input: `:8080 {
				redir * :8081 perm
			}`,
			expectError: true,
		},
		{
			input: `:8080 {
				redir * :8081 php
			}`,
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
