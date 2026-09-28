package httpcaddyfile

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestMatcherSyntax(t *testing.T) {
	for i, tc := range []struct {
		input          string
		expectError    bool
		expectContains string
	}{
		{
			input: `http://localhost
			@debug {
				query showdebug=1
			}
			`,
			expectError: false,
		},
		{
			input: `http://localhost
			@debug {
				query bad format
			}
			`,
			expectError: true,
		},
		{
			input: `http://localhost
			@debug {
				not {
					path /somepath*
				}
			}
			`,
			expectError: false,
		},
		{
			input: `http://localhost
			@debug {
				not path /somepath*
			}
			`,
			expectError: false,
		},
		{
			input: `http://localhost
			@debug not path /somepath*
			`,
			expectError: false,
		},
		{
			input: `http://localhost {
				@test {
					path /test
				}
				@test {
					path /other
				}
				respond @test "hello"
			}
			`,
			expectError:    true,
			expectContains: "is defined more than once",
		},
		{
			input: `(snippet) {
				@{args[0]} {
					path /{args[0]}
				}
				respond @{args[0]} "hello"
			}
			http://localhost {
				import snippet foo
				import snippet bar
			}
			`,
			expectError: false,
		},
		{
			input: `@matcher {
				path /matcher-not-allowed/outside-of-site-block/*
			}
			http://localhost
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

		if err != nil && tc.expectContains != "" {
			if !strings.Contains(err.Error(), tc.expectContains) {
				t.Errorf("Test %d error message mismatch: expected to contain %q, got %q",
					i, tc.expectContains, err.Error())
			}
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

func TestGlobalOptions(t *testing.T) {
	for i, tc := range []struct {
		input       string
		expectError bool
	}{
		{
			input: `
				{
					email test@example.com
				}
				:80
			`,
			expectError: false,
		},
		{
			input: `
				{
					admin off
				}
				:80
			`,
			expectError: false,
		},
		{
			input: `
				{
					admin 127.0.0.1:2020
				}
				:80
			`,
			expectError: false,
		},
		{
			input: `
				{
					admin {
						disabled false
					}
				}
				:80
			`,
			expectError: true,
		},
		{
			input: `
				{
					admin {
						enforce_origin
						origins 192.168.1.1:2020 127.0.0.1:2020
					}
				}
				:80
			`,
			expectError: false,
		},
		{
			input: `
				{
					admin 127.0.0.1:2020 {
						enforce_origin
						origins 192.168.1.1:2020 127.0.0.1:2020
					}
				}
				:80
			`,
			expectError: false,
		},
		{
			input: `
				{
					admin 192.168.1.1:2020 127.0.0.1:2020 {
						enforce_origin
						origins 192.168.1.1:2020 127.0.0.1:2020
					}
				}
				:80
			`,
			expectError: true,
		},
		{
			input: `
				{
					admin off {
						enforce_origin
						origins 192.168.1.1:2020 127.0.0.1:2020
					}
				}
				:80
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

func TestDefaultSNIWithoutHTTPS(t *testing.T) {
	caddyfileStr := `{
		default_sni my-sni.com
	}
	example.com {
	}`

	adapter := caddyfile.Adapter{
		ServerType: ServerType{},
	}

	result, _, err := adapter.Adapt([]byte(caddyfileStr), nil)
	if err != nil {
		t.Fatalf("Failed to adapt Caddyfile: %v", err)
	}

	var config struct {
		Apps struct {
			HTTP struct {
				Servers map[string]*caddyhttp.Server `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}

	if err := json.Unmarshal(result, &config); err != nil {
		t.Fatalf("Failed to unmarshal JSON config: %v", err)
	}

	server, ok := config.Apps.HTTP.Servers["srv0"]
	if !ok {
		t.Fatalf("Expected server 'srv0' to be created")
	}

	if len(server.TLSConnPolicies) == 0 {
		t.Fatalf("Expected TLS connection policies to be generated, got none")
	}

	found := false
	for _, policy := range server.TLSConnPolicies {
		if policy.DefaultSNI == "my-sni.com" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected default_sni 'my-sni.com' in TLS connection policies, but it was missing. Generated JSON: %s", string(result))
	}
}

// TestBindProtocolsMergedAcrossDirectives ensures that the protocols declared
// by every bind directive resolving to the same listener address are unioned
// together, instead of each bind directive discarding the ones before it.
func TestBindProtocolsMergedAcrossDirectives(t *testing.T) {
	for i, tc := range []struct {
		name            string
		input           string
		expectListen    []string
		expectProtocols [][]string
	}{
		{
			name: "two bind directives on the same address",
			input: `example.com {
	bind 127.0.0.1 {
		protocols h1
	}
	bind 127.0.0.1 {
		protocols h2
	}
}`,
			expectListen:    []string{"127.0.0.1:443"},
			expectProtocols: [][]string{{"h1", "h2"}},
		},
		{
			name: "later bind without protocols does not clear earlier ones",
			input: `example.com {
	bind 127.0.0.1 {
		protocols h1 h3
	}
	bind 127.0.0.1
}`,
			expectListen:    []string{"127.0.0.1:443"},
			expectProtocols: [][]string{{"h1", "h3"}},
		},
		{
			name: "a single bind directive is unaffected",
			input: `example.com {
	bind 127.0.0.1 {
		protocols h1
	}
}`,
			expectListen:    []string{"127.0.0.1:443"},
			expectProtocols: [][]string{{"h1"}},
		},
		{
			name: "bind directives on distinct addresses stay separate",
			input: `example.com {
	bind 127.0.0.1 {
		protocols h1
	}
	bind 127.0.0.2 {
		protocols h2
	}
}`,
			expectListen:    []string{"127.0.0.1:443", "127.0.0.2:443"},
			expectProtocols: [][]string{{"h1"}, {"h2"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			adapter := caddyfile.Adapter{ServerType: ServerType{}}
			result, _, err := adapter.Adapt([]byte(tc.input), nil)
			if err != nil {
				t.Fatalf("Failed to adapt Caddyfile: %v", err)
			}

			var config struct {
				Apps struct {
					HTTP struct {
						Servers map[string]*caddyhttp.Server `json:"servers"`
					} `json:"http"`
				} `json:"apps"`
			}
			if err := json.Unmarshal(result, &config); err != nil {
				t.Fatalf("Failed to unmarshal JSON config: %v", err)
			}

			server, ok := config.Apps.HTTP.Servers["srv0"]
			if !ok {
				t.Fatalf("Expected server 'srv0' to be created; got JSON: %s", result)
			}

			if !slices.Equal(server.Listen, tc.expectListen) {
				t.Errorf("Test %d: expected listen addresses %v, got %v", i, tc.expectListen, server.Listen)
			}
			if len(server.ListenProtocols) != len(tc.expectProtocols) {
				t.Errorf("Test %d: expected listen protocols %v, got %v; generated JSON: %s",
					i, tc.expectProtocols, server.ListenProtocols, result)
			} else {
				for j := range tc.expectProtocols {
					if !slices.Equal(server.ListenProtocols[j], tc.expectProtocols[j]) {
						t.Errorf("Test %d: expected listen protocols %v, got %v; generated JSON: %s",
							i, tc.expectProtocols, server.ListenProtocols, result)
						break
					}
				}
			}
		})
	}
}
