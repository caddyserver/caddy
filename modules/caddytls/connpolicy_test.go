// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddytls

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestClientAuthenticationUnmarshalCaddyfileWithDirectiveName(t *testing.T) {
	const test_der_1 = `MIIDSzCCAjOgAwIBAgIUfIRObjWNUA4jxQ/0x8BOCvE2Vw4wDQYJKoZIhvcNAQELBQAwFjEUMBIGA1UEAwwLRWFzeS1SU0EgQ0EwHhcNMTkwODI4MTYyNTU5WhcNMjkwODI1MTYyNTU5WjAWMRQwEgYDVQQDDAtFYXN5LVJTQSBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK5m5elxhQfMp/3aVJ4JnpN9PUSz6LlP6LePAPFU7gqohVVFVtDkChJAG3FNkNQNlieVTja/bgH9IcC6oKbROwdY1h0MvNV8AHHigvl03WuJD8g2ReVFXXwsnrPmKXCFzQyMI6TYk3m2gYrXsZOU1GLnfMRC3KAMRgE2F45twOs9hqG169YJ6mM2eQjzjCHWI6S2/iUYvYxRkCOlYUbLsMD/AhgAf1plzg6LPqNxtdlwxZnA0ytgkmhK67HtzJu0+ovUCsMv0RwcMhsEo9T8nyFAGt9XLZ63X5WpBCTUApaAUhnG0XnerjmUWb6eUWw4zev54sEfY5F3x002iQaW6cECAwEAAaOBkDCBjTAdBgNVHQ4EFgQU4CBUbZsS2GaNIkGRz/cBsD5ivjswUQYDVR0jBEowSIAU4CBUbZsS2GaNIkGRz/cBsD5ivjuhGqQYMBYxFDASBgNVBAMMC0Vhc3ktUlNBIENBghR8hE5uNY1QDiPFD/THwE4K8TZXDjAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEAKB3V4HIzoiO/Ch6WMj9bLJ2FGbpkMrcb/Eq01hT5zcfKD66lVS1MlK+cRL446Z2b2KDP1oFyVs+qmrmtdwrWgD+nfe2sBmmIHo9m9KygMkEOfG3MghGTEcS+0cTKEcoHYWYyOqQh6jnedXY8Cdm4GM1hAc9MiL3/sqV8YCVSLNnkoNysmr06/rZ0MCUZPGUtRmfd0heWhrfzAKw2HLgX+RAmpOE2MZqWcjvqKGyaRiaZks4nJkP6521aC2Lgp0HhCz1j8/uQ5ldoDszCnu/iro0NAsNtudTMD+YoLQxLqdleIh6CW+illc2VdXwj7mn6J04yns9jfE2jRjW/yTLFuQ==`
	const test_cert_file_1 = "../../caddytest/caddy.ca.cer"
	type args struct {
		d *caddyfile.Dispenser
	}
	tests := []struct {
		name     string
		args     args
		expected ClientAuthentication
		wantErr  bool
	}{
		{
			name: "empty client_auth block does not error",
			args: args{
				d: caddyfile.NewTestDispenser(
					`client_auth {
					}`,
				),
			},
			wantErr: false,
		},
		{
			name: "providing both 'trust_pool' and 'trusted_ca_cert' returns an error",
			args: args{
				d: caddyfile.NewTestDispenser(
					`client_auth {
					trust_pool inline MIIDSzCCAjOgAwIBAgIUfIRObjWNUA4jxQ/0x8BOCvE2Vw4wDQYJKoZIhvcNAQELBQAwFjEUMBIGA1UEAwwLRWFzeS1SU0EgQ0EwHhcNMTkwODI4MTYyNTU5WhcNMjkwODI1MTYyNTU5WjAWMRQwEgYDVQQDDAtFYXN5LVJTQSBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK5m5elxhQfMp/3aVJ4JnpN9PUSz6LlP6LePAPFU7gqohVVFVtDkChJAG3FNkNQNlieVTja/bgH9IcC6oKbROwdY1h0MvNV8AHHigvl03WuJD8g2ReVFXXwsnrPmKXCFzQyMI6TYk3m2gYrXsZOU1GLnfMRC3KAMRgE2F45twOs9hqG169YJ6mM2eQjzjCHWI6S2/iUYvYxRkCOlYUbLsMD/AhgAf1plzg6LPqNxtdlwxZnA0ytgkmhK67HtzJu0+ovUCsMv0RwcMhsEo9T8nyFAGt9XLZ63X5WpBCTUApaAUhnG0XnerjmUWb6eUWw4zev54sEfY5F3x002iQaW6cECAwEAAaOBkDCBjTAdBgNVHQ4EFgQU4CBUbZsS2GaNIkGRz/cBsD5ivjswUQYDVR0jBEowSIAU4CBUbZsS2GaNIkGRz/cBsD5ivjuhGqQYMBYxFDASBgNVBAMMC0Vhc3ktUlNBIENBghR8hE5uNY1QDiPFD/THwE4K8TZXDjAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEAKB3V4HIzoiO/Ch6WMj9bLJ2FGbpkMrcb/Eq01hT5zcfKD66lVS1MlK+cRL446Z2b2KDP1oFyVs+qmrmtdwrWgD+nfe2sBmmIHo9m9KygMkEOfG3MghGTEcS+0cTKEcoHYWYyOqQh6jnedXY8Cdm4GM1hAc9MiL3/sqV8YCVSLNnkoNysmr06/rZ0MCUZPGUtRmfd0heWhrfzAKw2HLgX+RAmpOE2MZqWcjvqKGyaRiaZks4nJkP6521aC2Lgp0HhCz1j8/uQ5ldoDszCnu/iro0NAsNtudTMD+YoLQxLqdleIh6CW+illc2VdXwj7mn6J04yns9jfE2jRjW/yTLFuQ==
					trusted_ca_cert MIIDSzCCAjOgAwIBAgIUfIRObjWNUA4jxQ/0x8BOCvE2Vw4wDQYJKoZIhvcNAQELBQAwFjEUMBIGA1UEAwwLRWFzeS1SU0EgQ0EwHhcNMTkwODI4MTYyNTU5WhcNMjkwODI1MTYyNTU5WjAWMRQwEgYDVQQDDAtFYXN5LVJTQSBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK5m5elxhQfMp/3aVJ4JnpN9PUSz6LlP6LePAPFU7gqohVVFVtDkChJAG3FNkNQNlieVTja/bgH9IcC6oKbROwdY1h0MvNV8AHHigvl03WuJD8g2ReVFXXwsnrPmKXCFzQyMI6TYk3m2gYrXsZOU1GLnfMRC3KAMRgE2F45twOs9hqG169YJ6mM2eQjzjCHWI6S2/iUYvYxRkCOlYUbLsMD/AhgAf1plzg6LPqNxtdlwxZnA0ytgkmhK67HtzJu0+ovUCsMv0RwcMhsEo9T8nyFAGt9XLZ63X5WpBCTUApaAUhnG0XnerjmUWb6eUWw4zev54sEfY5F3x002iQaW6cECAwEAAaOBkDCBjTAdBgNVHQ4EFgQU4CBUbZsS2GaNIkGRz/cBsD5ivjswUQYDVR0jBEowSIAU4CBUbZsS2GaNIkGRz/cBsD5ivjuhGqQYMBYxFDASBgNVBAMMC0Vhc3ktUlNBIENBghR8hE5uNY1QDiPFD/THwE4K8TZXDjAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEAKB3V4HIzoiO/Ch6WMj9bLJ2FGbpkMrcb/Eq01hT5zcfKD66lVS1MlK+cRL446Z2b2KDP1oFyVs+qmrmtdwrWgD+nfe2sBmmIHo9m9KygMkEOfG3MghGTEcS+0cTKEcoHYWYyOqQh6jnedXY8Cdm4GM1hAc9MiL3/sqV8YCVSLNnkoNysmr06/rZ0MCUZPGUtRmfd0heWhrfzAKw2HLgX+RAmpOE2MZqWcjvqKGyaRiaZks4nJkP6521aC2Lgp0HhCz1j8/uQ5ldoDszCnu/iro0NAsNtudTMD+YoLQxLqdleIh6CW+illc2VdXwj7mn6J04yns9jfE2jRjW/yTLFuQ==
				}`),
			},
			wantErr: true,
		},
		{
			name: "trust_pool without a module argument returns an error",
			args: args{
				d: caddyfile.NewTestDispenser(
					`client_auth {
					trust_pool
				}`),
			},
			wantErr: true,
		},
		{
			name: "providing more than 1 mode produces an error",
			args: args{
				d: caddyfile.NewTestDispenser(`
					client_auth {
						mode require request
					}
				`),
			},
			wantErr: true,
		},
		{
			name: "not providing 'mode' argument produces an error",
			args: args{d: caddyfile.NewTestDispenser(`
				client_auth {
					mode
				}
			`)},
			wantErr: true,
		},
		{
			name: "providing a single 'mode' argument sets the mode",
			args: args{
				d: caddyfile.NewTestDispenser(`
					client_auth {
						mode require
					}
				`),
			},
			expected: ClientAuthentication{
				Mode: "require",
			},
			wantErr: false,
		},
		{
			name: "not providing an argument to 'trusted_ca_cert' produces an error",
			args: args{
				d: caddyfile.NewTestDispenser(`
				client_auth {
					trusted_ca_cert
				}
				`),
			},
			wantErr: true,
		},
		{
			name: "not providing an argument to 'trusted_leaf_cert' produces an error",
			args: args{
				d: caddyfile.NewTestDispenser(`
				client_auth {
					trusted_leaf_cert
				}
				`),
			},
			wantErr: true,
		},
		{
			name: "not providing an argument to 'trusted_ca_cert_file' produces an error",
			args: args{
				d: caddyfile.NewTestDispenser(`
				client_auth {
					trusted_ca_cert_file
				}
				`),
			},
			wantErr: true,
		},
		{
			name: "not providing an argument to 'trusted_leaf_cert_file' produces an error",
			args: args{
				d: caddyfile.NewTestDispenser(`
				client_auth {
					trusted_leaf_cert_file
				}
				`),
			},
			wantErr: true,
		},
		{
			name: "using 'trusted_ca_cert' adapts successfully",
			args: args{
				d: caddyfile.NewTestDispenser(fmt.Sprintf(`
				client_auth {
					trusted_ca_cert %s
				}`, test_der_1)),
			},
			expected: ClientAuthentication{
				CARaw: json.RawMessage(fmt.Sprintf(`{"provider":"inline","trusted_ca_certs":["%s"]}`, test_der_1)),
			},
		},
		{
			name: "using 'inline' trust_pool loads the module successfully",
			args: args{
				d: caddyfile.NewTestDispenser(fmt.Sprintf(`
					client_auth {
						trust_pool inline {
							trust_der	%s
						}
					}
				`, test_der_1)),
			},
			expected: ClientAuthentication{
				CARaw: json.RawMessage(fmt.Sprintf(`{"provider":"inline","trusted_ca_certs":["%s"]}`, test_der_1)),
			},
		},
		{
			name: "setting 'trusted_ca_cert' and 'trust_pool' produces an error",
			args: args{
				d: caddyfile.NewTestDispenser(fmt.Sprintf(`
				client_auth {
					trusted_ca_cert %s
					trust_pool inline {
						trust_der	%s
					}
				}`, test_der_1, test_der_1)),
			},
			wantErr: true,
		},
		{
			name: "setting 'trust_pool' and 'trusted_ca_cert' produces an error",
			args: args{
				d: caddyfile.NewTestDispenser(fmt.Sprintf(`
				client_auth {
					trust_pool inline {
						trust_der	%s
					}
					trusted_ca_cert %s
				}`, test_der_1, test_der_1)),
			},
			wantErr: true,
		},
		{
			name: "setting 'trust_pool' and 'trusted_ca_cert' produces an error",
			args: args{
				d: caddyfile.NewTestDispenser(fmt.Sprintf(`
				client_auth {
					trust_pool inline {
						trust_der	%s
					}
					trusted_ca_cert_file %s
				}`, test_der_1, test_cert_file_1)),
			},
			wantErr: true,
		},
		{
			name: "configuring 'trusted_ca_cert_file' without an argument is an error",
			args: args{
				d: caddyfile.NewTestDispenser(`
				client_auth {
					trusted_ca_cert_file
				}
				`),
			},
			wantErr: true,
		},
		{
			name: "configuring 'trusted_ca_cert_file' produces config with 'inline' provider",
			args: args{
				d: caddyfile.NewTestDispenser(fmt.Sprintf(`
				client_auth {
					trusted_ca_cert_file %s
				}`, test_cert_file_1),
				),
			},
			expected: ClientAuthentication{
				CARaw: json.RawMessage(fmt.Sprintf(`{"provider":"inline","trusted_ca_certs":["%s"]}`, test_der_1)),
			},
			wantErr: false,
		},
		{
			name: "configuring leaf certs does not conflict with 'trust_pool'",
			args: args{
				d: caddyfile.NewTestDispenser(fmt.Sprintf(`
				client_auth {
					trust_pool inline {
						trust_der	%s
					}
					trusted_leaf_cert %s
				}`, test_der_1, test_der_1)),
			},
			expected: ClientAuthentication{
				CARaw:            json.RawMessage(fmt.Sprintf(`{"provider":"inline","trusted_ca_certs":["%s"]}`, test_der_1)),
				TrustedLeafCerts: []string{test_der_1},
			},
		},
		{
			name: "providing trusted leaf certificate file loads the cert successfully",
			args: args{
				d: caddyfile.NewTestDispenser(fmt.Sprintf(`
				client_auth {
					trusted_leaf_cert_file %s
				}`, test_cert_file_1)),
			},
			expected: ClientAuthentication{
				TrustedLeafCerts: []string{test_der_1},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca := &ClientAuthentication{}
			if err := ca.UnmarshalCaddyfile(tt.args.d); (err != nil) != tt.wantErr {
				t.Errorf("ClientAuthentication.UnmarshalCaddyfile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(&tt.expected, ca) {
				t.Errorf("ClientAuthentication.UnmarshalCaddyfile() = %v, want %v", ca, tt.expected)
			}
		})
	}
}
