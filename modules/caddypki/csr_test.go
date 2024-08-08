package caddypki

import (
	"encoding/json"
	"testing"
)

func TestParseKeyType(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected keyType
		err      string
	}{
		{
			name:     "uppercase EC is recognized",
			input:    `"EC"`,
			expected: keyTypeEC,
		},
		{
			name:  "lowercase EC is rejected",
			input: `"ec"`,
			err:   "unknown key type: ec",
		},
		{
			name:  "mixed case EC is rejected",
			input: `"eC"`,
			err:   "unknown key type: eC",
		},
		{
			name:     "uppercase RSA is recognized",
			input:    `"RSA"`,
			expected: keyTypeRSA,
		},
		{
			name:  "lowercase rsa is rejected",
			input: `"rsa"`,
			err:   "unknown key type: rsa",
		},
		{
			name:  "mixed case RSA is rejected",
			input: `"RsA"`,
			err:   "unknown key type: RsA",
		},
		{
			name:     "uppercase OKP is recognized",
			input:    `"OKP"`,
			expected: keyTypeOKP,
		},
		{
			name:  "lowercase OKP is rejected",
			input: `"okp"`,
			err:   "unknown key type: okp",
		},
		{
			name:  "mixed case OKP is rejected",
			input: `"OkP"`,
			err:   "unknown key type: OkP",
		},
		{
			name:  "unknown key type is rejected",
			input: `"foo"`,
			err:   "unknown key type: foo",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var kt keyType

			err := json.Unmarshal([]byte(test.input), &kt)
			if test.err != "" {
				if err == nil {
					t.Errorf("expected error %q, but got nil", test.err)
				}
				if err.Error() != test.err {
					t.Errorf("expected error %q, but got %q", test.err, err.Error())
				}
				return
			}
			if err != nil {
				t.Errorf("expected no error, but got %q", err.Error())
				return
			}
			if kt != test.expected {
				t.Errorf("expected %v, but got %v", test.expected, kt)
			}
		})
	}
}

func TestCSRKeyParameterValidate(t *testing.T) {
	tests := []struct {
		name    string
		key     *keyParameters
		wantErr bool
	}{
		{
			name:    "empty request is valid",
			key:     nil,
			wantErr: false,
		},
		{
			name: "RSA with size 2048 is valid",
			key: &keyParameters{
				Type: keyTypeRSA,
				Size: 2048,
			},
			wantErr: false,
		},
		{
			name: "RSA with size less than 2048 is invalid",
			key: &keyParameters{
				Type: keyTypeRSA,
				Size: 1024,
			},
			wantErr: true,
		},
		{
			name: "EC key with curve P-256 is valid",
			key: &keyParameters{
				Type:  keyTypeEC,
				Curve: "P-256",
			},
			wantErr: false,
		},
		{
			name: "EC key with curve P-256 is valid",
			key: &keyParameters{
				Type:  keyTypeEC,
				Curve: "P-256",
			},
			wantErr: false,
		},
		{
			name: "EC key with curve P-384 is valid",
			key: &keyParameters{
				Type:  keyTypeEC,
				Curve: "P-384",
			},
			wantErr: false,
		},
		{
			name: "EC key with curve P-521 is valid",
			key: &keyParameters{
				Type:  keyTypeEC,
				Curve: "P-521",
			},
			wantErr: false,
		},
		{
			name: "EC key with unknown curve is invalid",
			key: &keyParameters{
				Type:  keyTypeEC,
				Curve: "foo",
			},
			wantErr: true,
		},
		{
			name: "EC key with Ed25519 curve is invalid",
			key: &keyParameters{
				Type:  keyTypeEC,
				Curve: "Ed25519",
			},
			wantErr: true,
		},
		{
			name: "EC key with X25519 curve is invalid",
			key: &keyParameters{
				Type:  keyTypeEC,
				Curve: "X25519",
			},
			wantErr: true,
		},
		{
			name: "OKP key with curve Ed25519 is valid",
			key: &keyParameters{
				Type:  keyTypeOKP,
				Curve: "Ed25519",
			},
			wantErr: false,
		},
		{
			name: "OKP key with curve X25519 is valid",
			key: &keyParameters{
				Type:  keyTypeOKP,
				Curve: "X25519",
			},
			wantErr: false,
		},
		{
			name: "OKP with unknown curve is invalid",
			key: &keyParameters{
				Type:  keyTypeOKP,
				Curve: "foo",
			},
			wantErr: true,
		},
		{
			name: "OKP key with curve P-256 is invalid",
			key: &keyParameters{
				Type:  keyTypeOKP,
				Curve: "P-256",
			},
			wantErr: true,
		},
		{
			name: "OKP key with curve P-384 is invalid",
			key: &keyParameters{
				Type:  keyTypeOKP,
				Curve: "P-384",
			},
			wantErr: true,
		},
		{
			name: "OKP key with curve P-521 is invalid",
			key: &keyParameters{
				Type:  keyTypeOKP,
				Curve: "P-521",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.key.validate(); (err != nil) != tt.wantErr {
				t.Errorf("keyParameter.validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseCurve(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected curve
		err      string
	}{
		{
			name:     "Ed25519 is recognized",
			input:    `"Ed25519"`,
			expected: curveEd25519,
		},
		{
			name:  "ed25519 is rejected",
			input: `"ed25519"`,
			err:   "unknown curve: ed25519",
		},
		{
			name:  "eD25519 is rejected",
			input: `"eD25519"`,
			err:   "unknown curve: eD25519",
		},
		{
			name:     "X25519 is recognized",
			input:    `"X25519"`,
			expected: curveX25519,
		},
		{
			name:  "x25519 is rejected",
			input: `"x25519"`,
			err:   "unknown curve: x25519",
		},
		{
			name:     "P-256 is recognized",
			input:    `"P-256"`,
			expected: curveP256,
		},
		{
			name:  "p-256 is rejected",
			input: `"p-256"`,
			err:   "unknown curve: p-256",
		},

		{
			name:     "P-384 is recognized",
			input:    `"P-384"`,
			expected: curveP384,
		},
		{
			name:  "p-384 is rejected",
			input: `"p-384"`,
			err:   "unknown curve: p-384",
		},

		{
			name:     "P-521 is recognized",
			input:    `"P-521"`,
			expected: curveP521,
		},
		{
			name:  "p-521 is rejected",
			input: `"p-521"`,
			err:   "unknown curve: p-521",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var kt curve

			err := json.Unmarshal([]byte(test.input), &kt)
			if test.err != "" {
				if err == nil {
					t.Errorf("expected error %q, but got nil", test.err)
				}
				if err.Error() != test.err {
					t.Errorf("expected error %q, but got %q", test.err, err.Error())
				}
				return
			}
			if err != nil {
				t.Errorf("expected no error, but got %q", err.Error())
				return
			}
			if kt != test.expected {
				t.Errorf("expected %v, but got %v", test.expected, kt)
			}
		})
	}
}

func TestRequestParametersValidation(t *testing.T) {
	tests := []struct {
		name string
		req  *requestParameters
		want bool
	}{
		{
			name: "nil request is invalid",
			req:  nil,
			want: false,
		},
		{
			name: "empty request is invalid",
			req:  &requestParameters{},
			want: false,
		},
		{
			name: "request containing empty SAN value is invalid",
			req: &requestParameters{
				SANs: []string{"example.com", "", "foo.com"},
			},
			want: false,
		},
		{
			name: "request with SANs is valid",
			req: &requestParameters{
				SANs: []string{"example.com"},
			},
			want: true,
		},
		{
			name: "request with non-empty CommonName is valid",
			req: &requestParameters{
				Subject: &subject{CommonName: "example.com"},
			},
			want: true,
		},
		{
			name: "request with empty-space CommonName is invalid",
			req: &requestParameters{
				Subject: &subject{CommonName: " "},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.req.valid(); got != tt.want {
				t.Errorf("requestParameters.valid() = %v, want %v", got, tt.want)
			}
		})
	}
}
