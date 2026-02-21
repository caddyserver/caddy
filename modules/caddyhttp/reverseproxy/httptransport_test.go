package reverseproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestHTTPTransportUnmarshalCaddyFileWithCaPools(t *testing.T) {
	const test_der_1 = `MIIDSzCCAjOgAwIBAgIUfIRObjWNUA4jxQ/0x8BOCvE2Vw4wDQYJKoZIhvcNAQELBQAwFjEUMBIGA1UEAwwLRWFzeS1SU0EgQ0EwHhcNMTkwODI4MTYyNTU5WhcNMjkwODI1MTYyNTU5WjAWMRQwEgYDVQQDDAtFYXN5LVJTQSBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK5m5elxhQfMp/3aVJ4JnpN9PUSz6LlP6LePAPFU7gqohVVFVtDkChJAG3FNkNQNlieVTja/bgH9IcC6oKbROwdY1h0MvNV8AHHigvl03WuJD8g2ReVFXXwsnrPmKXCFzQyMI6TYk3m2gYrXsZOU1GLnfMRC3KAMRgE2F45twOs9hqG169YJ6mM2eQjzjCHWI6S2/iUYvYxRkCOlYUbLsMD/AhgAf1plzg6LPqNxtdlwxZnA0ytgkmhK67HtzJu0+ovUCsMv0RwcMhsEo9T8nyFAGt9XLZ63X5WpBCTUApaAUhnG0XnerjmUWb6eUWw4zev54sEfY5F3x002iQaW6cECAwEAAaOBkDCBjTAdBgNVHQ4EFgQU4CBUbZsS2GaNIkGRz/cBsD5ivjswUQYDVR0jBEowSIAU4CBUbZsS2GaNIkGRz/cBsD5ivjuhGqQYMBYxFDASBgNVBAMMC0Vhc3ktUlNBIENBghR8hE5uNY1QDiPFD/THwE4K8TZXDjAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEAKB3V4HIzoiO/Ch6WMj9bLJ2FGbpkMrcb/Eq01hT5zcfKD66lVS1MlK+cRL446Z2b2KDP1oFyVs+qmrmtdwrWgD+nfe2sBmmIHo9m9KygMkEOfG3MghGTEcS+0cTKEcoHYWYyOqQh6jnedXY8Cdm4GM1hAc9MiL3/sqV8YCVSLNnkoNysmr06/rZ0MCUZPGUtRmfd0heWhrfzAKw2HLgX+RAmpOE2MZqWcjvqKGyaRiaZks4nJkP6521aC2Lgp0HhCz1j8/uQ5ldoDszCnu/iro0NAsNtudTMD+YoLQxLqdleIh6CW+illc2VdXwj7mn6J04yns9jfE2jRjW/yTLFuQ==`
	type args struct {
		d *caddyfile.Dispenser
	}
	tests := []struct {
		name              string
		args              args
		expectedTLSConfig TLSConfig
		wantErr           bool
	}{
		{
			name: "tls_trust_pool without a module argument returns an error",
			args: args{
				d: caddyfile.NewTestDispenser(
					`http {
					tls_trust_pool
				}`),
			},
			wantErr: true,
		},
		{
			name: "providing both 'tls_trust_pool' and 'tls_trusted_ca_certs' returns an error",
			args: args{
				d: caddyfile.NewTestDispenser(fmt.Sprintf(
					`http {
					tls_trust_pool inline %s
					tls_trusted_ca_certs %s
				}`, test_der_1, test_der_1)),
			},
			wantErr: true,
		},
		{
			name: "setting 'tls_trust_pool' and 'tls_trusted_ca_certs' produces an error",
			args: args{
				d: caddyfile.NewTestDispenser(fmt.Sprintf(
					`http {
					tls_trust_pool inline {
						trust_der	%s
					}
					tls_trusted_ca_certs %s
				}`, test_der_1, test_der_1)),
			},
			wantErr: true,
		},
		{
			name: "using 'inline' tls_trust_pool loads the module successfully",
			args: args{
				d: caddyfile.NewTestDispenser(fmt.Sprintf(
					`http {
						tls_trust_pool inline {
							trust_der	%s
						}
					}
				`, test_der_1)),
			},
			expectedTLSConfig: TLSConfig{CARaw: json.RawMessage(fmt.Sprintf(`{"provider":"inline","trusted_ca_certs":["%s"]}`, test_der_1))},
		},
		{
			name: "setting 'tls_trusted_ca_certs' and 'tls_trust_pool' produces an error",
			args: args{
				d: caddyfile.NewTestDispenser(fmt.Sprintf(
					`http {
						tls_trusted_ca_certs %s
						tls_trust_pool inline {
							trust_der	%s
						}
				}`, test_der_1, test_der_1)),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ht := &HTTPTransport{}
			if err := ht.UnmarshalCaddyfile(tt.args.d); (err != nil) != tt.wantErr {
				t.Errorf("HTTPTransport.UnmarshalCaddyfile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(&tt.expectedTLSConfig, ht.TLS) {
				t.Errorf("HTTPTransport.UnmarshalCaddyfile() = %v, want %v", ht, tt.expectedTLSConfig)
			}
		})
	}
}

func TestHTTPTransport_RequestHeaderOps_TLS(t *testing.T) {
	var ht HTTPTransport
	// When TLS is nil, expect no header ops
	if ops := ht.RequestHeaderOps(); ops != nil {
		t.Fatalf("expected nil HeaderOps when TLS is nil, got: %#v", ops)
	}

	// When TLS is configured, expect a HeaderOps that sets Host
	ht.TLS = &TLSConfig{}
	ops := ht.RequestHeaderOps()
	if ops == nil {
		t.Fatal("expected non-nil HeaderOps when TLS is set")
	}
	if ops.Set == nil {
		t.Fatalf("expected ops.Set to be non-nil, got nil")
	}
	if got := ops.Set.Get("Host"); got != "{http.reverse_proxy.upstream.hostport}" {
		t.Fatalf("unexpected Host value; want placeholder, got: %s", got)
	}
}

// TestHTTPTransport_DialTLSContext_ProxyProtocol verifies that when TLS and
// ProxyProtocol are both enabled, DialTLSContext is set. This is critical because
// ProxyProtocol modifies req.URL.Host to include client info with "->" separator
// (e.g., "[2001:db8::1]:12345->127.0.0.1:443"), which breaks Go's address parsing.
// Without a custom DialTLSContext, Go's HTTP library would fail with
// "too many colons in address" when trying to parse the mangled host.
func TestHTTPTransport_DialTLSContext_ProxyProtocol(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	tests := []struct {
		name                    string
		tls                     *TLSConfig
		proxyProtocol           string
		serverNameHasPlaceholder bool
		expectDialTLSContext    bool
	}{
		{
			name:                 "no TLS, no proxy protocol",
			tls:                  nil,
			proxyProtocol:        "",
			expectDialTLSContext: false,
		},
		{
			name:                 "TLS without proxy protocol",
			tls:                  &TLSConfig{},
			proxyProtocol:        "",
			expectDialTLSContext: false,
		},
		{
			name:                 "TLS with proxy protocol v1",
			tls:                  &TLSConfig{},
			proxyProtocol:        "v1",
			expectDialTLSContext: true,
		},
		{
			name:                 "TLS with proxy protocol v2",
			tls:                  &TLSConfig{},
			proxyProtocol:        "v2",
			expectDialTLSContext: true,
		},
		{
			name:                     "TLS with placeholder ServerName",
			tls:                      &TLSConfig{ServerName: "{http.request.host}"},
			proxyProtocol:            "",
			serverNameHasPlaceholder: true,
			expectDialTLSContext:     true,
		},
		{
			name:                     "TLS with placeholder ServerName and proxy protocol",
			tls:                      &TLSConfig{ServerName: "{http.request.host}"},
			proxyProtocol:            "v2",
			serverNameHasPlaceholder: true,
			expectDialTLSContext:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ht := &HTTPTransport{
				TLS:           tt.tls,
				ProxyProtocol: tt.proxyProtocol,
			}

			rt, err := ht.NewTransport(ctx)
			if err != nil {
				t.Fatalf("NewTransport() error = %v", err)
			}

			hasDialTLSContext := rt.DialTLSContext != nil
			if hasDialTLSContext != tt.expectDialTLSContext {
				t.Errorf("DialTLSContext set = %v, want %v", hasDialTLSContext, tt.expectDialTLSContext)
			}
		})
	}
}

