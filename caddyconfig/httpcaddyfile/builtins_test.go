package httpcaddyfile

import (
	"strings"
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
					core mock
					output file foo.log
				}
			}
			`,
			output:      `{"logging":{"logs":{"default":{"exclude":["http.log.access.log0"]},"log0":{"writer":{"filename":"foo.log","output":"file"},"core":{"module":"mock"},"include":["http.log.access.log0"]}}},"apps":{"http":{"servers":{"srv0":{"listen":[":8080"],"logs":{"default_logger_name":"log0"}}}}}}`,
			expectError: false,
		},
		{
			input: `:8080 {
				log {
					format filter {
						wrap console
						fields {
							request>remote_ip ip_mask {
								ipv4 24
								ipv6 32
							}
						}
					}
				}
			}
			`,
			output:      `{"logging":{"logs":{"default":{"exclude":["http.log.access.log0"]},"log0":{"encoder":{"fields":{"request\u003eremote_ip":{"filter":"ip_mask","ipv4_cidr":24,"ipv6_cidr":32}},"format":"filter","wrap":{"format":"console"}},"include":["http.log.access.log0"]}}},"apps":{"http":{"servers":{"srv0":{"listen":[":8080"],"logs":{"default_logger_name":"log0"}}}}}}`,
			expectError: false,
		},
		{
			input: `:8080 {
				log name-override {
					core mock
					output file foo.log
				}
			}
			`,
			output:      `{"logging":{"logs":{"default":{"exclude":["http.log.access.name-override"]},"name-override":{"writer":{"filename":"foo.log","output":"file"},"core":{"module":"mock"},"include":["http.log.access.name-override"]}}},"apps":{"http":{"servers":{"srv0":{"listen":[":8080"],"logs":{"default_logger_name":"name-override"}}}}}}`,
			expectError: false,
		},
		{
			input: `:8080 {
				log {
					sampling {
						interval 2
						first 3
						thereafter 4
					}
				}
			}
			`,
			output:      `{"logging":{"logs":{"default":{"exclude":["http.log.access.log0"]},"log0":{"sampling":{"interval":2,"first":3,"thereafter":4},"include":["http.log.access.log0"]}}},"apps":{"http":{"servers":{"srv0":{"listen":[":8080"],"logs":{"default_logger_name":"log0"}}}}}}`,
			expectError: false,
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
			// this is now allowed so a Location header
			// can be written and consumed by JS
			// in the case of XHR requests
			input: `:8080 {
				redir * :8081 401
			}`,
			expectError: false,
		},
		{
			input: `:8080 {
				redir * :8081 402
			}`,
			expectError: true,
		},
		{
			input: `:8080 {
				redir * :8081 {http.reverse_proxy.status_code}
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

func TestImportErrorLine(t *testing.T) {
	for i, tc := range []struct {
		input     string
		errorFunc func(err error) bool
	}{
		{
			input: `(t1) {
					abort {args[:]}
				}
				:8080 {
					import t1
					import t1 true
				}`,
			errorFunc: func(err error) bool {
				return err != nil && strings.Contains(err.Error(), "Caddyfile:6 (import t1)")
			},
		},
		{
			input: `(t1) {
					abort {args[:]}
				}
				:8080 {
					import t1 true
				}`,
			errorFunc: func(err error) bool {
				return err != nil && strings.Contains(err.Error(), "Caddyfile:5 (import t1)")
			},
		},
		{
			input: `
				import testdata/import_variadic_snippet.txt
				:8080 {
					import t1 true
				}`,
			errorFunc: func(err error) bool {
				return err == nil
			},
		},
		{
			input: `
				import testdata/import_variadic_with_import.txt
				:8080 {
					import t1 true
					import t2 true
				}`,
			errorFunc: func(err error) bool {
				return err == nil
			},
		},
	} {
		adapter := caddyfile.Adapter{
			ServerType: ServerType{},
		}

		_, _, err := adapter.Adapt([]byte(tc.input), nil)

		if !tc.errorFunc(err) {
			t.Errorf("Test %d error expectation failed, got %s", i, err)
			continue
		}
	}
}

func TestNestedImport(t *testing.T) {
	for i, tc := range []struct {
		input     string
		errorFunc func(err error) bool
	}{
		{
			input: `(t1) {
						respond {args[0]} {args[1]}
					}
					
					(t2) {
						import t1 {args[0]} 202
					}
					
					:8080 {
						handle {
							import t2 "foobar"
						}
					}`,
			errorFunc: func(err error) bool {
				return err == nil
			},
		},
		{
			input: `(t1) {
						respond {args[:]}
					}
					
					(t2) {
						import t1 {args[0]} {args[1]}
					}
					
					:8080 {
						handle {
							import t2 "foobar" 202
						}
					}`,
			errorFunc: func(err error) bool {
				return err == nil
			},
		},
		{
			input: `(t1) {
						respond {args[0]} {args[1]}
					}
					
					(t2) {
						import t1 {args[:]}
					}
					
					:8080 {
						handle {
							import t2 "foobar" 202
						}
					}`,
			errorFunc: func(err error) bool {
				return err == nil
			},
		},
	} {
		adapter := caddyfile.Adapter{
			ServerType: ServerType{},
		}

		_, _, err := adapter.Adapt([]byte(tc.input), nil)

		if !tc.errorFunc(err) {
			t.Errorf("Test %d error expectation failed, got %s", i, err)
			continue
		}
	}
}
