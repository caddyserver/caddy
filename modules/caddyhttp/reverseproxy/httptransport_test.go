package reverseproxy

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

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
