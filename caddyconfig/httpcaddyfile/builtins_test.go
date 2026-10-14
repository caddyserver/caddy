package httpcaddyfile_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	_ "github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile/blocktypes/globalblock"
	_ "github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile/blocktypes/httpserverblock"
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
						interval 2s
						first 3
						thereafter 4
					}
				}
			}
			`,
			output:      `{"logging":{"logs":{"default":{"exclude":["http.log.access.log0"]},"log0":{"sampling":{"interval":2000000000,"first":3,"thereafter":4},"include":["http.log.access.log0"]}}},"apps":{"http":{"servers":{"srv0":{"listen":[":8080"],"logs":{"default_logger_name":"log0"}}}}}}`,
			expectError: false,
		},
		{
			input: `:8080 {
				log {
					output stdout
					output file foo.log
				}
			}
			`,
			expectError: true,
		},
		{
			input: `:8080 {
				log {
					format json
					format console
				}
			}
			`,
			expectError: true,
		},
		{
			input: `:8080 {
				log {
					level INFO
					level DEBUG
				}
			}
			`,
			expectError: true,
		},
		{
			input: `:8080 {
				log {
					sampling {
						interval 1s
						interval 2s
					}
				}
			}
			`,
			expectError: true,
		},
	} {

		adapter := caddyfile.Adapter{
			ServerType: httpcaddyfile.ServerType{},
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
			ServerType: httpcaddyfile.ServerType{},
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
			ServerType: httpcaddyfile.ServerType{},
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
			ServerType: httpcaddyfile.ServerType{},
		}

		_, _, err := adapter.Adapt([]byte(tc.input), nil)

		if !tc.errorFunc(err) {
			t.Errorf("Test %d error expectation failed, got %s", i, err)
			continue
		}
	}
}

func TestLogLevelDirectiveSyntax(t *testing.T) {
	for _, tc := range []struct {
		directive string
		wantError bool
	}{
		{"log_level DEBUG", false}, {"log_level info", false},
		{"log_level WARN", false}, {"log_level ERROR", false},
		{"log_level /warnings WARN", false},
		{"log_level", true}, {"log_level INFO WARN", true},
		{"log_level invalid", true}, {"log_level DPANIC", true},
		{"log_level PANIC", true}, {"log_level FATAL", true},
		{"log_level WARN {\n foo\n}", true},
	} {
		t.Run(tc.directive, func(t *testing.T) {
			adapter := caddyfile.Adapter{ServerType: ServerType{}}
			result, _, err := adapter.Adapt([]byte(":8080 {\n"+tc.directive+"\n}"), nil)
			if tc.wantError {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var config struct {
				Apps struct {
					HTTP struct {
						Servers map[string]struct {
							Routes []struct {
								Match  []map[string]any
								Handle []struct {
									Handler string
									Level   string `json:"log_level"`
								}
							}
						}
					}
				}
			}
			if err := json.Unmarshal(result, &config); err != nil {
				t.Fatal(err)
			}
			routes := config.Apps.HTTP.Servers["srv0"].Routes
			if len(routes) != 1 || len(routes[0].Handle) != 1 {
				t.Fatalf("unexpected routes: %s", result)
			}
			handler := routes[0].Handle[0]
			args := strings.Fields(tc.directive)
			if handler.Handler != "vars" || handler.Level != strings.ToLower(args[len(args)-1]) {
				t.Fatalf("unexpected handler: %s", result)
			}
			if strings.Contains(tc.directive, "/warnings") && len(routes[0].Match) != 1 {
				t.Fatalf("missing matcher: %s", result)
			}
		})
	}
}

func TestLogLevelDirectiveOrder(t *testing.T) {
	for _, input := range []string{
		"log_level /api/private/* ERROR\nlog_level /api/* DEBUG\nlog_level INFO",
		"log_level INFO\nlog_level /api/* DEBUG\nlog_level /api/private/* ERROR",
	} {
		t.Run(input, func(t *testing.T) {
			adapter := caddyfile.Adapter{ServerType: ServerType{}}
			result, _, err := adapter.Adapt([]byte(":8080 {\n"+input+"\n}"), nil)
			if err != nil {
				t.Fatal(err)
			}
			var config struct {
				Apps struct {
					HTTP struct {
						Servers map[string]struct {
							Routes []struct {
								Handle []struct {
									Level string `json:"log_level"`
								}
							}
						}
					}
				}
			}
			if err := json.Unmarshal(result, &config); err != nil {
				t.Fatal(err)
			}
			var levels []string
			for _, route := range config.Apps.HTTP.Servers["srv0"].Routes {
				for _, handler := range route.Handle {
					levels = append(levels, handler.Level)
				}
			}
			if got := strings.Join(levels, ","); got != "info,debug,error" {
				t.Fatalf("expected broadest log_level first, got %q: %s", got, result)
			}
		})
	}
}
