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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

// newSelectionCert creates a self-signed certificate with the given
// serial number, subject organization, key type, and tags, for
// exercising certificate selection policies.
func newSelectionCert(t *testing.T, serial int64, org string, useRSA bool, tags []string) certmagic.Certificate {
	t.Helper()

	var privKey crypto.Signer
	var err error
	if useRSA {
		privKey, err = rsa.GenerateKey(rand.Reader, 2048)
	} else {
		privKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			CommonName:   "caddytls.test",
			Organization: []string{org},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, privKey.Public(), privKey)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}

	return certmagic.Certificate{
		Certificate: tls.Certificate{
			Certificate: [][]byte{der},
			PrivateKey:  privKey,
			Leaf:        leaf,
		},
		Tags: tags,
	}
}

func TestCustomCertSelectionPolicySelectCertificate(t *testing.T) {
	certAlpha := newSelectionCert(t, 1000, "Alpha", false, []string{"alpha", "common"})
	certBeta := newSelectionCert(t, 2000, "Beta", true, []string{"beta", "common"})
	certGamma := newSelectionCert(t, 3000, "Gamma", false, []string{"gamma", "common", "extra"})
	choices := []certmagic.Certificate{certAlpha, certBeta, certGamma}

	hello := &tls.ClientHelloInfo{}

	for i, tc := range []struct {
		policy         CustomCertSelectionPolicy
		expectedSerial int64
		wantErr        bool
	}{
		{
			// no criteria; all certs are viable, first one wins
			policy:         CustomCertSelectionPolicy{},
			expectedSerial: 1000,
		},
		{
			policy: CustomCertSelectionPolicy{
				SerialNumber: []bigInt{{Int: *big.NewInt(2000)}},
			},
			expectedSerial: 2000,
		},
		{
			policy: CustomCertSelectionPolicy{
				SerialNumber: []bigInt{{Int: *big.NewInt(9999)}},
			},
			wantErr: true,
		},
		{
			policy: CustomCertSelectionPolicy{
				SubjectOrganization: []string{"Gamma"},
			},
			expectedSerial: 3000,
		},
		{
			policy: CustomCertSelectionPolicy{
				SubjectOrganization: []string{"Delta"},
			},
			wantErr: true,
		},
		{
			policy: CustomCertSelectionPolicy{
				PublicKeyAlgorithm: PublicKeyAlgorithm(x509.RSA),
			},
			expectedSerial: 2000,
		},
		{
			policy: CustomCertSelectionPolicy{
				PublicKeyAlgorithm: PublicKeyAlgorithm(x509.ECDSA),
			},
			expectedSerial: 1000,
		},
		{
			policy: CustomCertSelectionPolicy{
				AnyTag: []string{"gamma"},
			},
			expectedSerial: 3000,
		},
		{
			policy: CustomCertSelectionPolicy{
				AnyTag: []string{"nonexistent", "beta"},
			},
			expectedSerial: 2000,
		},
		{
			policy: CustomCertSelectionPolicy{
				AnyTag: []string{"nonexistent"},
			},
			wantErr: true,
		},
		{
			policy: CustomCertSelectionPolicy{
				AllTags: []string{"common", "extra"},
			},
			expectedSerial: 3000,
		},
		{
			policy: CustomCertSelectionPolicy{
				AllTags: []string{"common", "nonexistent"},
			},
			wantErr: true,
		},
		{
			policy: CustomCertSelectionPolicy{
				PublicKeyAlgorithm: PublicKeyAlgorithm(x509.ECDSA),
				AllTags:            []string{"common", "extra"},
			},
			expectedSerial: 3000,
		},
		{
			// criteria match different certs, so no single cert satisfies all
			policy: CustomCertSelectionPolicy{
				PublicKeyAlgorithm: PublicKeyAlgorithm(x509.RSA),
				AnyTag:             []string{"gamma"},
			},
			wantErr: true,
		},
	} {
		cert, err := tc.policy.SelectCertificate(hello, choices)
		if tc.wantErr {
			if err == nil {
				t.Errorf("Test %d: expected error but got none", i)
			}
			continue
		}
		if err != nil {
			t.Errorf("Test %d: unexpected error: %v", i, err)
			continue
		}
		if cert.Leaf.SerialNumber.Int64() != tc.expectedSerial {
			t.Errorf("Test %d: expected certificate with serial %d, got %d",
				i, tc.expectedSerial, cert.Leaf.SerialNumber.Int64())
		}
	}
}

func TestCustomCertSelectionPolicyUnmarshalCaddyfile(t *testing.T) {
	for i, tc := range []struct {
		input     string
		expected  CustomCertSelectionPolicy
		expectErr string
	}{
		{
			input: `cert_selection {
				serial_number 1234 5678
				subject_organization Org1 Org2
				public_key_algorithm ecdsa
				any_tag t1 t2
				all_tags t3 t4
			}`,
			expected: CustomCertSelectionPolicy{
				SerialNumber:        []bigInt{{Int: *big.NewInt(1234)}, {Int: *big.NewInt(5678)}},
				SubjectOrganization: []string{"Org1", "Org2"},
				PublicKeyAlgorithm:  PublicKeyAlgorithm(x509.ECDSA),
				AnyTag:              []string{"t1", "t2"},
				AllTags:             []string{"t3", "t4"},
			},
		},
		{
			input:    `cert_selection`,
			expected: CustomCertSelectionPolicy{},
		},
		{
			input:     `cert_selection same_line_arg`,
			expectErr: "wrong argument count",
		},
		{
			input: `cert_selection {
				serial_number
			}`,
			expectErr: "wrong argument count",
		},
		{
			input: `cert_selection {
				serial_number not_a_number
			}`,
			expectErr: "invalid big.int",
		},
		{
			input: `cert_selection {
				public_key_algorithm rsa
				public_key_algorithm ecdsa
			}`,
			expectErr: "duplicate",
		},
		{
			input: `cert_selection {
				public_key_algorithm rsa dsa
			}`,
			expectErr: "wrong argument count",
		},
		{
			input: `cert_selection {
				public_key_algorithm ed25519
			}`,
			expectErr: "unrecognized public key algorithm",
		},
		{
			input: `cert_selection {
				unknown_option value
			}`,
			expectErr: "wrong argument count",
		},
		{
			input: `cert_selection {
				any_tag t1 {
					nested
				}
			}`,
			expectErr: "blocks are not supported",
		},
	} {
		var p CustomCertSelectionPolicy
		err := p.UnmarshalCaddyfile(caddyfile.NewTestDispenser(tc.input))
		if tc.expectErr != "" {
			if err == nil {
				t.Errorf("Test %d: expected error containing %q but got none", i, tc.expectErr)
			} else if !strings.Contains(err.Error(), tc.expectErr) {
				t.Errorf("Test %d: expected error containing %q, got: %v", i, tc.expectErr, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("Test %d: unexpected error: %v", i, err)
			continue
		}
		if len(p.SerialNumber) != len(tc.expected.SerialNumber) {
			t.Errorf("Test %d: expected %d serial numbers, got %d",
				i, len(tc.expected.SerialNumber), len(p.SerialNumber))
		} else {
			for j := range p.SerialNumber {
				snExpected, snActual := tc.expected.SerialNumber[j].Int, p.SerialNumber[j].Int
				if snActual.Cmp(&snExpected) != 0 {
					t.Errorf("Test %d: expected serial number %s at index %d, got %s",
						i, snExpected.String(), j, snActual.String())
				}
			}
		}
		if !slices.Equal(p.SubjectOrganization, tc.expected.SubjectOrganization) {
			t.Errorf("Test %d: expected subject organizations %v, got %v",
				i, tc.expected.SubjectOrganization, p.SubjectOrganization)
		}
		if p.PublicKeyAlgorithm != tc.expected.PublicKeyAlgorithm {
			t.Errorf("Test %d: expected public key algorithm %v, got %v",
				i, tc.expected.PublicKeyAlgorithm, p.PublicKeyAlgorithm)
		}
		if !slices.Equal(p.AnyTag, tc.expected.AnyTag) {
			t.Errorf("Test %d: expected any_tag %v, got %v", i, tc.expected.AnyTag, p.AnyTag)
		}
		if !slices.Equal(p.AllTags, tc.expected.AllTags) {
			t.Errorf("Test %d: expected all_tags %v, got %v", i, tc.expected.AllTags, p.AllTags)
		}
	}
}

func TestBigIntJSON(t *testing.T) {
	var bi bigInt
	if err := bi.UnmarshalJSON([]byte(`"12345678901234567890"`)); err != nil {
		t.Fatalf("unmarshaling valid big integer: %v", err)
	}
	if bi.String() != "12345678901234567890" {
		t.Errorf("expected 12345678901234567890, got %s", bi.String())
	}

	out, err := bi.MarshalJSON()
	if err != nil {
		t.Fatalf("marshaling: %v", err)
	}
	if string(out) != `"12345678901234567890"` {
		t.Errorf(`expected "12345678901234567890", got %s`, out)
	}

	if err := bi.UnmarshalJSON([]byte("null")); err != nil {
		t.Errorf("unmarshaling null should be a no-op, got error: %v", err)
	}

	if err := new(bigInt).UnmarshalJSON([]byte(`"not-a-number"`)); err == nil {
		t.Error("expected error unmarshaling invalid big integer, got none")
	}

	if err := new(bigInt).UnmarshalJSON([]byte(`12345`)); err == nil {
		t.Error("expected error unmarshaling non-string JSON value, got none")
	}
}
