package httpcaddyfile

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestWindowsRootTrailingBackslash(t *testing.T) {
	adapter := caddyfile.Adapter{ServerType: ServerType{}}
	input := "http://localhost {\nroot * C:\\site\\\nrespond ok\n}\n"
	rootJSON, err := json.Marshal(`C:\site\`)
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range []string{input, strings.ReplaceAll(input, "\n", "\r\n")} {
		before, _, err := adapter.Adapt([]byte(in), nil)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(before), `"root":`+string(rootJSON)) {
			t.Fatalf("Windows root not preserved in adapted config: %s", before)
		}
		after, _, err := adapter.Adapt(caddyfile.Format([]byte(in)), nil)
		if err != nil {
			t.Fatal(err)
		}
		if string(before) != string(after) {
			t.Fatalf("formatting changed adapted JSON:\nbefore: %s\nafter: %s", before, after)
		}
	}
}

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

func TestTLSConnectionPoliciesAreIsolatedAcrossListeners(t *testing.T) {
	caddyfileStr := `(mtls) {
		tls {
			client_auth {
				mode require_and_verify
				trust_pool file /tmp/root.crt
			}
		}
	}

	abc.domain.com, abc.domain.com:2000 {
		import mtls
		respond "first"
	}

	domain.domain.com {
		import mtls
		respond "second"
	}

	ghi.domain.com, ghi.domain.com:2000 {
		import mtls
		respond "third"
	}`

	adapter := caddyfile.Adapter{ServerType: ServerType{}}
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

	for listener, expectedNames := range map[string][]string{
		":2000": {"abc.domain.com", "ghi.domain.com"},
		":443":  {"abc.domain.com", "domain.domain.com", "ghi.domain.com"},
	} {
		var server *caddyhttp.Server
		for _, candidate := range config.Apps.HTTP.Servers {
			if slices.Contains(candidate.Listen, listener) {
				server = candidate
				break
			}
		}
		if server == nil {
			t.Fatalf("Expected a server listening on %s", listener)
		}

		var names []string
		for _, policy := range server.TLSConnPolicies {
			if policy.ClientAuthentication == nil {
				continue
			}
			if policy.ClientAuthentication.Mode != "require_and_verify" {
				t.Fatalf("Expected %s client authentication on %s, got %s", "require_and_verify", listener, policy.ClientAuthentication.Mode)
			}
			var policyNames []string
			if err := json.Unmarshal(policy.MatchersRaw["sni"], &policyNames); err != nil {
				t.Fatalf("Failed to unmarshal SNI matcher for %s: %v", listener, err)
			}
			names = append(names, policyNames...)
		}

		slices.Sort(names)
		if !slices.Equal(names, expectedNames) {
			t.Errorf("Expected client authentication for %v on %s, got %v", expectedNames, listener, names)
		}
	}
}

func TestShorthandDefaults(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{`{host} {query.user}`, `{http.request.host} {http.request.uri.query.user}`},
		{`{path:-/index.html}`, `{http.request.uri.path:-/index.html}`},
		{`{header.X-User:-{cookie.user:-{query.user:-anonymous}}}`, `{http.request.header.X-User:-{http.request.cookie.user:-{http.request.uri.query.user:-anonymous}}}`},
		{`{vars.name:-{re.route.1:-{host}}}`, `{http.vars.name:-{http.regexp.route.1:-{http.request.host}}}`},
		{`{path:-a:b}`, `{http.request.uri.path:-a:b}`},
		{`{"message":"literal:-value"}`, `{"message":"literal:-value"}`},
		{`{http.request.header.X-User:-header.X-User}`, `{http.request.header.X-User:-header.X-User}`},
		{`{prefixheader.X-User:-{query.user}}`, `{prefixheader.X-User:-{http.request.uri.query.user}}`},
		{`{query.user.suffix:-{vars.name}}`, `{query.user.suffix:-{http.vars.name}}`},
		{`{hostsuffix:-host}`, `{hostsuffix:-host}`},
		{`{missing:-header.X-User query.user host}`, `{missing:-header.X-User query.user host}`},
		{`{missing:-\{host\}}`, `{missing:-\{host\}}`},
		{`\{host}`, `\{host}`},
		{`\{query.user}`, `\{query.user}`},
		{`\\{host}`, `\\{host}`},
		{`{\{host}, \{http.request.host}}`, `{\{host}, \{http.request.host}}`},
		{`\{"message":"{host}","user":"{query.user}"\}`, `\{"message":"{http.request.host}","user":"{http.request.uri.query.user}"\}`},
		{`{missing:-\\{host}}`, `{missing:-\\{http.request.host}}`},
		{`{"message":"{host}","fallback":"{query.user:-anonymous}"}`, `{"message":"{http.request.host}","fallback":"{http.request.uri.query.user:-anonymous}"}`},
	} {
		segment := caddyfile.Segment{{Text: tc.input}}
		NewShorthandReplacer().ApplyToSegment(&segment)
		if got := segment[0].Text; got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.input, got, tc.want)
		}
	}
}

func TestEscapedShorthandOutput(t *testing.T) {
	segment := caddyfile.Segment{{Text: `\{host}`}}
	NewShorthandReplacer().ApplyToSegment(&segment)
	repl := caddy.NewReplacer()
	repl.Set("http.request.host", "example.com")
	if got := repl.ReplaceAll(segment[0].Text, ""); got != "{host}" {
		t.Fatalf("escaped shorthand output = %q; want literal {host}", got)
	}
}
