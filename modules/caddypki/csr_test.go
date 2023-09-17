package caddypki

import (
	"encoding/json"
	"reflect"
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
			name:  "lowercase EC is recognized",
			input: `"ec"`,
			err:   "unknown key type: ec",
		},
		{
			name:  "mixed case EC is recognized",
			input: `"eC"`,
			err:   "unknown key type: eC",
		},
		{
			name:     "uppercase RSA is recognized",
			input:    `"RSA"`,
			expected: keyTypeRSA,
		},
		{
			name:  "lowercase rsa is not accepted",
			input: `"rsa"`,
			err:   "unknown key type: rsa",
		},
		{
			name:  "mixed case RSA is not accepted",
			input: `"RsA"`,
			err:   "unknown key type: RsA",
		},
		{
			name:     "uppercase OKP is recognized",
			input:    `"OKP"`,
			expected: keyTypeOKP,
		},
		{
			name:  "lowercase OKP is not accepted",
			input: `"okp"`,
			err:   "unknown key type: okp",
		},
		{
			name:  "mixed case OKP is not accepted",
			input: `"OkP"`,
			err:   "unknown key type: OkP",
		},
		{
			name:  "unknown key type is an error",
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

func TestCSRRequestValidate(t *testing.T) {
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
			c := csrRequest{
				Key: tt.key,
			}
			if err := c.validate(); (err != nil) != tt.wantErr {
				t.Errorf("csrRequest.validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCSRRequestUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		request string
		want    csrRequest
		err     string
	}{
		{
			name:    "empty request is valid",
			request: "{}",
			want: csrRequest{
				Key: nil,
			},
		},
		{
			name:    "RSA with size 2048 is valid",
			request: `{"key":{"type":"RSA","size":2048}}`,
			want: csrRequest{
				Key: &keyParameters{
					Type: keyTypeRSA,
					Size: 2048,
				},
			},
		},
		{
			name:    "EC key with curve P-256 is valid",
			request: `{"key":{"type":"EC","curve":"P-256"}}`,
			want: csrRequest{
				Key: &keyParameters{
					Type:  keyTypeEC,
					Curve: "P-256",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c csrRequest
			err := json.Unmarshal([]byte(tt.request), &c)
			if tt.err != "" {
				if err == nil {
					t.Errorf("expected error %q, but got nil", tt.err)
				}
				if err.Error() != tt.err {
					t.Errorf("expected error %q, but got %q", tt.err, err.Error())
				}
			}
			if err != nil {
				t.Errorf("expected no error, but got %q", err.Error())
			}
			if !reflect.DeepEqual(c, tt.want) {
				t.Errorf("csrRequest.unmarshalJSON() = %v, want %v", c, tt.want)
			}
		})
	}
}
