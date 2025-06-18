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
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/pemutil"
)

func TestKeyPair_Load(t *testing.T) {
	rootSigner, err := keyutil.GenerateDefaultSigner()
	if err != nil {
		t.Fatalf("Failed creating signer: %v", err)
	}

	tmpl := &x509.Certificate{
		Subject:    pkix.Name{CommonName: "test-root"},
		IsCA:       true,
		MaxPathLen: 3,
	}
	rootBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, rootSigner.Public(), rootSigner)
	if err != nil {
		t.Fatalf("Creating root certificate failed: %v", err)
	}

	root, err := x509.ParseCertificate(rootBytes)
	if err != nil {
		t.Fatalf("Parsing root certificate failed: %v", err)
	}

	intermediateSigner, err := keyutil.GenerateDefaultSigner()
	if err != nil {
		t.Fatalf("Creating intermedaite signer failed: %v", err)
	}

	intermediateBytes, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		Subject:    pkix.Name{CommonName: "test-first-intermediate"},
		IsCA:       true,
		MaxPathLen: 2,
		NotAfter:   time.Now().Add(time.Hour),
	}, root, intermediateSigner.Public(), rootSigner)
	if err != nil {
		t.Fatalf("Creating intermediate certificate failed: %v", err)
	}

	intermediate, err := x509.ParseCertificate(intermediateBytes)
	if err != nil {
		t.Fatalf("Parsing intermediate certificate failed: %v", err)
	}

	var chainContents []byte
	chain := []*x509.Certificate{intermediate, root}
	for _, cert := range chain {
		b, err := pemutil.Serialize(cert)
		if err != nil {
			t.Fatalf("Failed serializing intermediate certificate: %v", err)
		}
		chainContents = append(chainContents, pem.EncodeToMemory(b)...)
	}

	dir := t.TempDir()
	rootCertFile := filepath.Join(dir, "root.pem")
	if _, err = pemutil.Serialize(root, pemutil.WithFilename(rootCertFile)); err != nil {
		t.Fatalf("Failed serializing root certificate: %v", err)
	}
	rootKeyFile := filepath.Join(dir, "root.key")
	if _, err = pemutil.Serialize(rootSigner, pemutil.WithFilename(rootKeyFile)); err != nil {
		t.Fatalf("Failed serializing root key: %v", err)
	}
	intermediateCertFile := filepath.Join(dir, "intermediate.pem")
	if _, err = pemutil.Serialize(intermediate, pemutil.WithFilename(intermediateCertFile)); err != nil {
		t.Fatalf("Failed serializing intermediate certificate: %v", err)
	}
	intermediateKeyFile := filepath.Join(dir, "intermediate.key")
	if _, err = pemutil.Serialize(intermediateSigner, pemutil.WithFilename(intermediateKeyFile)); err != nil {
		t.Fatalf("Failed serializing intermediate key: %v", err)
	}
	chainFile := filepath.Join(dir, "chain.pem")
	if err := os.WriteFile(chainFile, chainContents, 0644); err != nil {
		t.Fatalf("Failed writing intermediate chain: %v", err)
	}

	t.Run("ok/single-certificate-without-signer", func(t *testing.T) {
		kp := KeyPair{
			Certificate: rootCertFile,
		}
		chain, signer, err := kp.Load()
		if err != nil {
			t.Fatalf("Failed loading KeyPair: %v", err)
		}
		if len(chain) != 1 {
			t.Errorf("Expected 1 certificate in chain; got %d", len(chain))
		}
		if signer != nil {
			t.Error("Expected no signer to be returned")
		}
	})

	t.Run("ok/single-certificate-with-signer", func(t *testing.T) {
		kp := KeyPair{
			Certificate: rootCertFile,
			PrivateKey:  rootKeyFile,
		}
		chain, signer, err := kp.Load()
		if err != nil {
			t.Fatalf("Failed loading KeyPair: %v", err)
		}
		if len(chain) != 1 {
			t.Errorf("Expected 1 certificate in chain; got %d", len(chain))
		}
		if signer == nil {
			t.Error("Expected signer to be returned")
		}
	})

	t.Run("ok/multiple-certificates-with-signer", func(t *testing.T) {
		kp := KeyPair{
			Certificate: chainFile,
			PrivateKey:  intermediateKeyFile,
		}
		chain, signer, err := kp.Load()
		if err != nil {
			t.Fatalf("Failed loading KeyPair: %v", err)
		}
		if len(chain) != 2 {
			t.Errorf("Expected 1 certificate in chain; got %d", len(chain))
		}
		if signer == nil {
			t.Error("Expected signer to be returned")
		}
	})

	t.Run("fail/non-matching-public-key", func(t *testing.T) {
		kp := KeyPair{
			Certificate: intermediateCertFile,
			PrivateKey:  rootKeyFile,
		}
		chain, signer, err := kp.Load()
		if err == nil {
			t.Error("Expected loading KeyPair to return an error")
		}
		if chain != nil {
			t.Error("Expected no chain to be returned")
		}
		if signer != nil {
			t.Error("Expected no signer to be returned")
		}
	})
}
