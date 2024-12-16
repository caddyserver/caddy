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

package caddypki

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/caddyserver/certmagic"
)

func pemDecodeSingleCert(pemDER []byte) (*x509.Certificate, error) {
	pemBlock, remaining := pem.Decode(pemDER)
	if pemBlock == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if len(remaining) > 0 {
		return nil, fmt.Errorf("input contained more than a single PEM block")
	}
	if pemBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("expected PEM block type to be CERTIFICATE, but got '%s'", pemBlock.Type)
	}
	return x509.ParseCertificate(pemBlock.Bytes)
}

func pemEncodeCert(der []byte) ([]byte, error) {
	return pemEncode("CERTIFICATE", der)
}

func pemEncode(blockType string, b []byte) ([]byte, error) {
	var buf bytes.Buffer
	err := pem.Encode(&buf, &pem.Block{Type: blockType, Bytes: b})
	return buf.Bytes(), err
}

func trusted(cert *x509.Certificate) bool {
	chains, err := cert.Verify(x509.VerifyOptions{})
	return len(chains) > 0 && err == nil
}

// KeyPair represents a public-private key pair, where the
// public key is also called a certificate.
type KeyPair struct {
	// The certificate. By default, this should be the path to
	// a PEM file unless format is something else.
	Certificate string `json:"certificate,omitempty"`

	// The private key. By default, this should be the path to
	// a PEM file unless format is something else.
	PrivateKey string `json:"private_key,omitempty"`

	// The format in which the certificate and private
	// key are provided. Default: pem_file
	Format string `json:"format,omitempty"`
}

// Load loads the certificate and key.
func (kp KeyPair) Load() (*x509.Certificate, crypto.Signer, error) {
	switch kp.Format {
	case "", "pem_file":
		certData, err := os.ReadFile(kp.Certificate)
		if err != nil {
			return nil, nil, err
		}
		cert, err := pemDecodeSingleCert(certData)
		if err != nil {
			return nil, nil, err
		}

		var key crypto.Signer
		if kp.PrivateKey != "" {
			keyData, err := os.ReadFile(kp.PrivateKey)
			if err != nil {
				return nil, nil, err
			}
			key, err = certmagic.PEMDecodePrivateKey(keyData)
			if err != nil {
				return nil, nil, err
			}
		}

		return cert, key, nil

	default:
		return nil, nil, fmt.Errorf("unsupported format: %s", kp.Format)
	}
}
