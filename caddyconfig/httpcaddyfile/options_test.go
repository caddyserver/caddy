package httpcaddyfile_test

import (
	"encoding/json"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	_ "github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile/blocktypes/globalblock"
	_ "github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile/blocktypes/httpserverblock"
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
			ServerType: httpcaddyfile.ServerType{},
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
				tls_resolvers 1.1.1.1
			}
			example.com {
			}`,
			expectResolvers: []string{"1.1.1.1"},
			expectError:     false,
		},
		{
			name: "two resolvers",
			input: `{
				tls_resolvers 1.1.1.1 8.8.8.8
			}
			example.com {
			}`,
			expectResolvers: []string{"1.1.1.1", "8.8.8.8"},
			expectError:     false,
		},
		{
			name: "multiple resolvers",
			input: `{
				tls_resolvers 1.1.1.1 8.8.8.8 9.9.9.9
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
				ServerType: httpcaddyfile.ServerType{},
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

func TestGlobalCertIssuerAppliesToImplicitACMEIssuer(t *testing.T) {
	adapter := caddyfile.Adapter{
		ServerType: httpcaddyfile.ServerType{},
	}

	input := `{
		cert_issuer acme {
			disable_tlsalpn_challenge
		}
	}
	report.company.intern {
		tls {
			ca https://deglacme01.company.intern/acme/acme/directory
			ca_root /etc/certs/company_root2.crt
		}
		respond "ok"
	}`

	out, _, err := adapter.Adapt([]byte(input), nil)
	if err != nil {
		t.Fatalf("adapting caddyfile: %v", err)
	}

	var config struct {
		Apps struct {
			TLS *caddytls.TLS `json:"tls"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(out, &config); err != nil {
		t.Fatalf("unmarshaling adapted config: %v", err)
	}
	if config.Apps.TLS == nil || config.Apps.TLS.Automation == nil {
		t.Fatal("expected tls automation config")
	}

	var subjectPolicy *caddytls.AutomationPolicy
	for _, ap := range config.Apps.TLS.Automation.Policies {
		if len(ap.SubjectsRaw) == 1 && ap.SubjectsRaw[0] == "report.company.intern" {
			subjectPolicy = ap
			break
		}
	}
	if subjectPolicy == nil {
		t.Fatal("expected subject-specific automation policy")
	}
	if len(subjectPolicy.IssuersRaw) != 1 {
		t.Fatalf("expected one issuer for subject-specific policy, got %d", len(subjectPolicy.IssuersRaw))
	}

	var issuer caddytls.ACMEIssuer
	if err := json.Unmarshal(subjectPolicy.IssuersRaw[0], &issuer); err != nil {
		t.Fatalf("unmarshaling issuer: %v", err)
	}
	if issuer.CA != "https://deglacme01.company.intern/acme/acme/directory" {
		t.Fatalf("expected custom ACME CA, got %q", issuer.CA)
	}
	if len(issuer.TrustedRootsPEMFiles) != 1 || issuer.TrustedRootsPEMFiles[0] != "/etc/certs/company_root2.crt" {
		t.Fatalf("expected trusted roots to include site CA root, got %v", issuer.TrustedRootsPEMFiles)
	}
	if issuer.Challenges == nil || issuer.Challenges.TLSALPN == nil || !issuer.Challenges.TLSALPN.Disabled {
		t.Fatalf("expected tls-alpn challenge to be disabled, got %#v", issuer.Challenges)
	}
}
