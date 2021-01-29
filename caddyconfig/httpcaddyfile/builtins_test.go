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
				log /foo {
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
