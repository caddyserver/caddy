package caddytls

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	_ "github.com/caddyserver/caddy/v2/modules/filestorage"
)

const (
	test_der_1       = `MIIDSzCCAjOgAwIBAgIUfIRObjWNUA4jxQ/0x8BOCvE2Vw4wDQYJKoZIhvcNAQELBQAwFjEUMBIGA1UEAwwLRWFzeS1SU0EgQ0EwHhcNMTkwODI4MTYyNTU5WhcNMjkwODI1MTYyNTU5WjAWMRQwEgYDVQQDDAtFYXN5LVJTQSBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK5m5elxhQfMp/3aVJ4JnpN9PUSz6LlP6LePAPFU7gqohVVFVtDkChJAG3FNkNQNlieVTja/bgH9IcC6oKbROwdY1h0MvNV8AHHigvl03WuJD8g2ReVFXXwsnrPmKXCFzQyMI6TYk3m2gYrXsZOU1GLnfMRC3KAMRgE2F45twOs9hqG169YJ6mM2eQjzjCHWI6S2/iUYvYxRkCOlYUbLsMD/AhgAf1plzg6LPqNxtdlwxZnA0ytgkmhK67HtzJu0+ovUCsMv0RwcMhsEo9T8nyFAGt9XLZ63X5WpBCTUApaAUhnG0XnerjmUWb6eUWw4zev54sEfY5F3x002iQaW6cECAwEAAaOBkDCBjTAdBgNVHQ4EFgQU4CBUbZsS2GaNIkGRz/cBsD5ivjswUQYDVR0jBEowSIAU4CBUbZsS2GaNIkGRz/cBsD5ivjuhGqQYMBYxFDASBgNVBAMMC0Vhc3ktUlNBIENBghR8hE5uNY1QDiPFD/THwE4K8TZXDjAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEAKB3V4HIzoiO/Ch6WMj9bLJ2FGbpkMrcb/Eq01hT5zcfKD66lVS1MlK+cRL446Z2b2KDP1oFyVs+qmrmtdwrWgD+nfe2sBmmIHo9m9KygMkEOfG3MghGTEcS+0cTKEcoHYWYyOqQh6jnedXY8Cdm4GM1hAc9MiL3/sqV8YCVSLNnkoNysmr06/rZ0MCUZPGUtRmfd0heWhrfzAKw2HLgX+RAmpOE2MZqWcjvqKGyaRiaZks4nJkP6521aC2Lgp0HhCz1j8/uQ5ldoDszCnu/iro0NAsNtudTMD+YoLQxLqdleIh6CW+illc2VdXwj7mn6J04yns9jfE2jRjW/yTLFuQ==`
	test_cert_file_1 = "../../caddytest/caddy.ca.cer"
)

func TestInlineCAPoolUnmarshalCaddyfile(t *testing.T) {
	type args struct {
		d *caddyfile.Dispenser
	}
	tests := []struct {
		name     string
		args     args
		expected InlineCAPool
		wantErr  bool
	}{
		{
			name: "configuring no certificatest produces an error",
			args: args{
				d: caddyfile.NewTestDispenser(`
					inline {
					}
				`),
			},
			wantErr: true,
		},
		{
			name: "configuring certificates as arguments in-line produces an error",
			args: args{
				d: caddyfile.NewTestDispenser(fmt.Sprintf(`
					inline %s
				`, test_der_1)),
			},
			wantErr: true,
		},
		{
			name: "single cert",
			args: args{
				d: caddyfile.NewTestDispenser(fmt.Sprintf(`
				inline {
					trust_der %s
				}
				`, test_der_1)),
			},
			expected: InlineCAPool{
				TrustedCACerts: []string{test_der_1},
			},
			wantErr: false,
		},
		{
			name: "multiple certs in one line",
			args: args{
				d: caddyfile.NewTestDispenser(fmt.Sprintf(`
				inline {
					trust_der %s %s
				}
				`, test_der_1, test_der_1),
				),
			},
			expected: InlineCAPool{
				TrustedCACerts: []string{test_der_1, test_der_1},
			},
		},
		{
			name: "multiple certs in multiple lines",
			args: args{
				d: caddyfile.NewTestDispenser(fmt.Sprintf(`
					inline {
						trust_der %s
						trust_der %s
					}
				`, test_der_1, test_der_1)),
			},
			expected: InlineCAPool{
				TrustedCACerts: []string{test_der_1, test_der_1},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			icp := &InlineCAPool{}
			if err := icp.UnmarshalCaddyfile(tt.args.d); (err != nil) != tt.wantErr {
				t.Errorf("InlineCAPool.UnmarshalCaddyfile() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && !reflect.DeepEqual(&tt.expected, icp) {
				t.Errorf("InlineCAPool.UnmarshalCaddyfile() = %v, want %v", icp, tt.expected)
			}
		})
	}
}

func TestFileCAPoolUnmarshalCaddyfile(t *testing.T) {
	type args struct {
		d *caddyfile.Dispenser
	}
	tests := []struct {
		name     string
		expected FileCAPool
		args     args
		wantErr  bool
	}{
		{
			name: "configuring no certificatest produces an error",
			args: args{
				d: caddyfile.NewTestDispenser(`
					file {
					}
				`),
			},
			wantErr: true,
		},
		{
			name: "configuring certificates as arguments in-line produces an error",
			args: args{
				d: caddyfile.NewTestDispenser(fmt.Sprintf(`
				file %s
				`, test_cert_file_1)),
			},
			expected: FileCAPool{
				TrustedCACertPEMFiles: []string{test_cert_file_1},
			},
		},
		{
			name: "single cert",
			args: args{
				d: caddyfile.NewTestDispenser(fmt.Sprintf(`
				file {
					pem_file %s
				}
				`, test_cert_file_1)),
			},
			expected: FileCAPool{
				TrustedCACertPEMFiles: []string{test_cert_file_1},
			},
			wantErr: false,
		},
		{
			name: "multiple certs inline and in-block are merged",
			args: args{
				d: caddyfile.NewTestDispenser(fmt.Sprintf(`
				file %s {
					pem_file %s
				}
				`, test_cert_file_1, test_cert_file_1)),
			},
			expected: FileCAPool{
				TrustedCACertPEMFiles: []string{test_cert_file_1, test_cert_file_1},
			},
			wantErr: false,
		},
		{
			name: "multiple certs in one line",
			args: args{
				d: caddyfile.NewTestDispenser(fmt.Sprintf(`
				file {
					pem_file %s %s
				}
				`, test_der_1, test_der_1),
				),
			},
			expected: FileCAPool{
				TrustedCACertPEMFiles: []string{test_der_1, test_der_1},
			},
		},
		{
			name: "multiple certs in multiple lines",
			args: args{
				d: caddyfile.NewTestDispenser(fmt.Sprintf(`
					file {
						pem_file %s
						pem_file %s
					}
				`, test_cert_file_1, test_cert_file_1)),
			},
			expected: FileCAPool{
				TrustedCACertPEMFiles: []string{test_cert_file_1, test_cert_file_1},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fcap := &FileCAPool{}
			if err := fcap.UnmarshalCaddyfile(tt.args.d); (err != nil) != tt.wantErr {
				t.Errorf("FileCAPool.UnmarshalCaddyfile() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && !reflect.DeepEqual(&tt.expected, fcap) {
				t.Errorf("FileCAPool.UnmarshalCaddyfile() = %v, want %v", fcap, tt.expected)
			}
		})
	}
}

func TestPKIRootCAPoolUnmarshalCaddyfile(t *testing.T) {
	type args struct {
		d *caddyfile.Dispenser
	}
	tests := []struct {
		name     string
		expected PKIRootCAPool
		args     args
		wantErr  bool
	}{
		{
			name: "configuring no certificatest produces an error",
			args: args{
				d: caddyfile.NewTestDispenser(`
					pki_root {
					}
				`),
			},
			wantErr: true,
		},
		{
			name: "single authority as arguments in-line",
			args: args{
				d: caddyfile.NewTestDispenser(`
				pki_root ca_1
				`),
			},
			expected: PKIRootCAPool{
				Authority: []string{"ca_1"},
			},
		},
		{
			name: "multiple authorities as arguments in-line",
			args: args{
				d: caddyfile.NewTestDispenser(`
				pki_root ca_1 ca_2
				`),
			},
			expected: PKIRootCAPool{
				Authority: []string{"ca_1", "ca_2"},
			},
		},
		{
			name: "single authority in block",
			args: args{
				d: caddyfile.NewTestDispenser(`
				pki_root {
					authority ca_1
				}`),
			},
			expected: PKIRootCAPool{
				Authority: []string{"ca_1"},
			},
			wantErr: false,
		},
		{
			name: "multiple authorities in one line",
			args: args{
				d: caddyfile.NewTestDispenser(`
				pki_root {
					authority ca_1 ca_2
				}`),
			},
			expected: PKIRootCAPool{
				Authority: []string{"ca_1", "ca_2"},
			},
		},
		{
			name: "multiple authorities in multiple lines",
			args: args{
				d: caddyfile.NewTestDispenser(`
					pki_root {
						authority ca_1
						authority ca_2
					}`),
			},
			expected: PKIRootCAPool{
				Authority: []string{"ca_1", "ca_2"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkir := &PKIRootCAPool{}
			if err := pkir.UnmarshalCaddyfile(tt.args.d); (err != nil) != tt.wantErr {
				t.Errorf("PKIRootCAPool.UnmarshalCaddyfile() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && !reflect.DeepEqual(&tt.expected, pkir) {
				t.Errorf("PKIRootCAPool.UnmarshalCaddyfile() = %v, want %v", pkir, tt.expected)
			}
		})
	}
}

func TestPKIIntermediateCAPoolUnmarshalCaddyfile(t *testing.T) {
	type args struct {
		d *caddyfile.Dispenser
	}
	tests := []struct {
		name     string
		expected PKIIntermediateCAPool
		args     args
		wantErr  bool
	}{
		{
			name: "configuring no certificatest produces an error",
			args: args{
				d: caddyfile.NewTestDispenser(`
				pki_intermediate {
				}`),
			},
			wantErr: true,
		},
		{
			name: "single authority as arguments in-line",
			args: args{
				d: caddyfile.NewTestDispenser(`pki_intermediate ca_1`),
			},
			expected: PKIIntermediateCAPool{
				Authority: []string{"ca_1"},
			},
		},
		{
			name: "multiple authorities as arguments in-line",
			args: args{
				d: caddyfile.NewTestDispenser(`pki_intermediate ca_1 ca_2`),
			},
			expected: PKIIntermediateCAPool{
				Authority: []string{"ca_1", "ca_2"},
			},
		},
		{
			name: "single authority in block",
			args: args{
				d: caddyfile.NewTestDispenser(`
				pki_intermediate {
					authority ca_1
				}`),
			},
			expected: PKIIntermediateCAPool{
				Authority: []string{"ca_1"},
			},
			wantErr: false,
		},
		{
			name: "multiple authorities in one line",
			args: args{
				d: caddyfile.NewTestDispenser(`
				pki_intermediate {
					authority ca_1 ca_2
				}`),
			},
			expected: PKIIntermediateCAPool{
				Authority: []string{"ca_1", "ca_2"},
			},
		},
		{
			name: "multiple authorities in multiple lines",
			args: args{
				d: caddyfile.NewTestDispenser(`
					pki_intermediate {
						authority ca_1
						authority ca_2
					}`),
			},
			expected: PKIIntermediateCAPool{
				Authority: []string{"ca_1", "ca_2"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pic := &PKIIntermediateCAPool{}
			if err := pic.UnmarshalCaddyfile(tt.args.d); (err != nil) != tt.wantErr {
				t.Errorf("PKIIntermediateCAPool.UnmarshalCaddyfile() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && !reflect.DeepEqual(&tt.expected, pic) {
				t.Errorf("PKIIntermediateCAPool.UnmarshalCaddyfile() = %v, want %v", pic, tt.expected)
			}
		})
	}
}

func TestStoragePoolUnmarshalCaddyfile(t *testing.T) {
	type args struct {
		d *caddyfile.Dispenser
	}
	tests := []struct {
		name     string
		args     args
		expected StoragePool
		wantErr  bool
	}{
		{
			name: "empty block",
			args: args{
				d: caddyfile.NewTestDispenser(`storage {
				}`),
			},
			expected: StoragePool{},
			wantErr:  false,
		},
		{
			name: "providing single storage key inline",
			args: args{
				d: caddyfile.NewTestDispenser(`storage key-1`),
			},
			expected: StoragePool{
				PEMKeys: []string{"key-1"},
			},
			wantErr: false,
		},
		{
			name: "providing multiple storage keys inline",
			args: args{
				d: caddyfile.NewTestDispenser(`storage key-1 key-2`),
			},
			expected: StoragePool{
				PEMKeys: []string{"key-1", "key-2"},
			},
			wantErr: false,
		},
		{
			name: "providing keys inside block without specifying storage type",
			args: args{
				d: caddyfile.NewTestDispenser(`
					storage {
						keys key-1 key-2
					}
				`),
			},
			expected: StoragePool{
				PEMKeys: []string{"key-1", "key-2"},
			},
			wantErr: false,
		},
		{
			name: "providing keys in-line and inside block merges them",
			args: args{
				d: caddyfile.NewTestDispenser(`storage key-1 key-2 key-3 {
					keys key-4 key-5
				}`),
			},
			expected: StoragePool{
				PEMKeys: []string{"key-1", "key-2", "key-3", "key-4", "key-5"},
			},
			wantErr: false,
		},
		{
			name: "specifying storage type in block",
			args: args{
				d: caddyfile.NewTestDispenser(`storage {
					storage file_system /var/caddy/storage
				}`),
			},
			expected: StoragePool{
				StorageRaw: json.RawMessage(`{"module":"file_system","root":"/var/caddy/storage"}`),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sp := &StoragePool{}
			if err := sp.UnmarshalCaddyfile(tt.args.d); (err != nil) != tt.wantErr {
				t.Errorf("StoragePool.UnmarshalCaddyfile() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && !reflect.DeepEqual(&tt.expected, sp) {
				t.Errorf("StoragePool.UnmarshalCaddyfile() = %s, want %s", sp.StorageRaw, tt.expected.StorageRaw)
			}
		})
	}
}

func TestTLSConfig_unmarshalCaddyfile(t *testing.T) {
	type args struct {
		d *caddyfile.Dispenser
	}
	tests := []struct {
		name     string
		args     args
		expected TLSConfig
		wantErr  bool
	}{
		{
			name: "no arguments is valid",
			args: args{
				d: caddyfile.NewTestDispenser(` {
				}`),
			},
			expected: TLSConfig{},
		},
		{
			name: "setting 'renegotiation' to 'never' is valid",
			args: args{
				d: caddyfile.NewTestDispenser(` {
					renegotiation never
				}`),
			},
			expected: TLSConfig{
				Renegotiation: "never",
			},
		},
		{
			name: "setting 'renegotiation' to 'once' is valid",
			args: args{
				d: caddyfile.NewTestDispenser(` {
					renegotiation once
				}`),
			},
			expected: TLSConfig{
				Renegotiation: "once",
			},
		},
		{
			name: "setting 'renegotiation' to 'freely' is valid",
			args: args{
				d: caddyfile.NewTestDispenser(` {
					renegotiation freely
				}`),
			},
			expected: TLSConfig{
				Renegotiation: "freely",
			},
		},
		{
			name: "setting 'renegotiation' to other than 'none', 'once, or 'freely' is invalid",
			args: args{
				d: caddyfile.NewTestDispenser(` {
					renegotiation foo
				}`),
			},
			wantErr: true,
		},
		{
			name: "setting 'renegotiation' without argument is invalid",
			args: args{
				d: caddyfile.NewTestDispenser(` {
					renegotiation
				}`),
			},
			wantErr: true,
		},
		{
			name: "setting 'ca' without argument is an error",
			args: args{
				d: caddyfile.NewTestDispenser(`{
					ca
				}`),
			},
			wantErr: true,
		},
		{
			name: "setting 'ca' to 'file' with in-line cert is valid",
			args: args{
				d: caddyfile.NewTestDispenser(`{
					ca file /var/caddy/ca.pem
				}`),
			},
			expected: TLSConfig{
				CARaw: []byte(`{"pem_files":["/var/caddy/ca.pem"],"provider":"file"}`),
			},
		},
		{
			name: "setting 'ca' to 'file' with appropriate block is valid",
			args: args{
				d: caddyfile.NewTestDispenser(`{
					ca file /var/caddy/ca.pem {
						pem_file /var/caddy/ca.pem
					}
				}`),
			},
			expected: TLSConfig{
				CARaw: []byte(`{"pem_files":["/var/caddy/ca.pem","/var/caddy/ca.pem"],"provider":"file"}`),
			},
		},
		{
			name: "setting 'ca' multiple times is an error",
			args: args{
				d: caddyfile.NewTestDispenser(fmt.Sprintf(`{
					ca file /var/caddy/ca.pem {
						pem_file /var/caddy/ca.pem
					}
					ca inline %s
				}`, test_der_1)),
			},
			wantErr: true,
		},
		{
			name: "setting 'handshake_timeout' without value is an error",
			args: args{
				d: caddyfile.NewTestDispenser(`{
					handshake_timeout
				}`),
			},
			wantErr: true,
		},
		{
			name: "setting 'handshake_timeout' properly is successful",
			args: args{
				d: caddyfile.NewTestDispenser(`{
					handshake_timeout 42m
				}`),
			},
			expected: TLSConfig{
				HandshakeTimeout: caddy.Duration(42 * time.Minute),
			},
		},
		{
			name: "setting 'server_name' without value is an error",
			args: args{
				d: caddyfile.NewTestDispenser(`{
					server_name
				}`),
			},
			wantErr: true,
		},
		{
			name: "setting 'server_name' properly is successful",
			args: args{
				d: caddyfile.NewTestDispenser(`{
					server_name example.com
				}`),
			},
			expected: TLSConfig{
				ServerName: "example.com",
			},
		},
		{
			name: "unsupported directives are errors",
			args: args{
				d: caddyfile.NewTestDispenser(`{
					foo
				}`),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := &TLSConfig{}
			if err := tr.unmarshalCaddyfile(tt.args.d); (err != nil) != tt.wantErr {
				t.Errorf("TLSConfig.unmarshalCaddyfile() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && !reflect.DeepEqual(&tt.expected, tr) {
				t.Errorf("TLSConfig.UnmarshalCaddyfile() = %v, want %v", tr, tt.expected)
			}
		})
	}
}

func TestHTTPCertPoolUnmarshalCaddyfile(t *testing.T) {
	type args struct {
		d *caddyfile.Dispenser
	}
	tests := []struct {
		name     string
		args     args
		expected HTTPCertPool
		wantErr  bool
	}{
		{
			name: "no block, inline http endpoint",
			args: args{
				d: caddyfile.NewTestDispenser(`http http://localhost/ca-certs`),
			},
			expected: HTTPCertPool{
				Endpoints: []string{"http://localhost/ca-certs"},
			},
			wantErr: false,
		},
		{
			name: "no block, inline https endpoint",
			args: args{
				d: caddyfile.NewTestDispenser(`http https://localhost/ca-certs`),
			},
			expected: HTTPCertPool{
				Endpoints: []string{"https://localhost/ca-certs"},
			},
			wantErr: false,
		},
		{
			name: "no block, mixed http and https endpoints inline",
			args: args{
				d: caddyfile.NewTestDispenser(`http http://localhost/ca-certs https://localhost/ca-certs`),
			},
			expected: HTTPCertPool{
				Endpoints: []string{"http://localhost/ca-certs", "https://localhost/ca-certs"},
			},
			wantErr: false,
		},
		{
			name: "multiple endpoints in separate lines in block",
			args: args{
				d: caddyfile.NewTestDispenser(`
					http {
						endpoints http://localhost/ca-certs
						endpoints http://remotehost/ca-certs
					}
				`),
			},
			expected: HTTPCertPool{
				Endpoints: []string{"http://localhost/ca-certs", "http://remotehost/ca-certs"},
			},
			wantErr: false,
		},
		{
			name: "endpoints defined inline and in block are merged",
			args: args{
				d: caddyfile.NewTestDispenser(`http http://localhost/ca-certs {
					endpoints http://remotehost/ca-certs
				}`),
			},
			expected: HTTPCertPool{
				Endpoints: []string{"http://localhost/ca-certs", "http://remotehost/ca-certs"},
			},
			wantErr: false,
		},
		{
			name: "multiple endpoints defined in block on the same line",
			args: args{
				d: caddyfile.NewTestDispenser(`http {
					endpoints http://remotehost/ca-certs http://localhost/ca-certs
				}`),
			},
			expected: HTTPCertPool{
				Endpoints: []string{"http://remotehost/ca-certs", "http://localhost/ca-certs"},
			},
			wantErr: false,
		},
		{
			name: "declaring 'endpoints' in block without argument is an error",
			args: args{
				d: caddyfile.NewTestDispenser(`http {
					endpoints
				}`),
			},
			wantErr: true,
		},
		{
			name: "multiple endpoints in separate lines in block",
			args: args{
				d: caddyfile.NewTestDispenser(`
					http {
						endpoints http://localhost/ca-certs
						endpoints http://remotehost/ca-certs
						tls {
							renegotiation freely
						}
					}
				`),
			},
			expected: HTTPCertPool{
				Endpoints: []string{"http://localhost/ca-certs", "http://remotehost/ca-certs"},
				TLS: &TLSConfig{
					Renegotiation: "freely",
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hcp := &HTTPCertPool{}
			if err := hcp.UnmarshalCaddyfile(tt.args.d); (err != nil) != tt.wantErr {
				t.Errorf("HTTPCertPool.UnmarshalCaddyfile() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && !reflect.DeepEqual(&tt.expected, hcp) {
				t.Errorf("HTTPCertPool.UnmarshalCaddyfile() = %v, want %v", hcp, tt.expected)
			}
		})
	}
}
