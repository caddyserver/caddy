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
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddypki"
	"go.uber.org/zap"

	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/pemutil"
)

func TestInternalIssuer_Issue(t *testing.T) {
	rootSigner, err := keyutil.GenerateDefaultSigner()
	if err != nil {
		t.Fatalf("Creating root signer failed: %v", err)
	}

	tmpl := &x509.Certificate{
		Subject:    pkix.Name{CommonName: "test-root"},
		IsCA:       true,
		MaxPathLen: 3,
		NotAfter:   time.Now().Add(7 * 24 * time.Hour),
		NotBefore:  time.Now().Add(-7 * 24 * time.Hour),
	}
	rootBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, rootSigner.Public(), rootSigner)
	if err != nil {
		t.Fatalf("Creating root certificate failed: %v", err)
	}

	root, err := x509.ParseCertificate(rootBytes)
	if err != nil {
		t.Fatalf("Parsing root certificate failed: %v", err)
	}

	firstIntermediateSigner, err := keyutil.GenerateDefaultSigner()
	if err != nil {
		t.Fatalf("Creating intermedaite signer failed: %v", err)
	}

	firstIntermediateBytes, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		Subject:    pkix.Name{CommonName: "test-first-intermediate"},
		IsCA:       true,
		MaxPathLen: 2,
		NotAfter:   time.Now().Add(24 * time.Hour),
		NotBefore:  time.Now().Add(-24 * time.Hour),
	}, root, firstIntermediateSigner.Public(), rootSigner)
	if err != nil {
		t.Fatalf("Creating intermediate certificate failed: %v", err)
	}

	firstIntermediate, err := x509.ParseCertificate(firstIntermediateBytes)
	if err != nil {
		t.Fatalf("Parsing intermediate certificate failed: %v", err)
	}

	secondIntermediateSigner, err := keyutil.GenerateDefaultSigner()
	if err != nil {
		t.Fatalf("Creating second intermedaite signer failed: %v", err)
	}

	secondIntermediateBytes, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		Subject:    pkix.Name{CommonName: "test-second-intermediate"},
		IsCA:       true,
		MaxPathLen: 2,
		NotAfter:   time.Now().Add(24 * time.Hour),
		NotBefore:  time.Now().Add(-24 * time.Hour),
	}, firstIntermediate, secondIntermediateSigner.Public(), firstIntermediateSigner)
	if err != nil {
		t.Fatalf("Creating second intermediate certificate failed: %v", err)
	}

	secondIntermediate, err := x509.ParseCertificate(secondIntermediateBytes)
	if err != nil {
		t.Fatalf("Parsing second intermediate certificate failed: %v", err)
	}

	dir := t.TempDir()
	storageDir := filepath.Join(dir, "certmagic")
	rootCertFile := filepath.Join(dir, "root.pem")
	if _, err = pemutil.Serialize(root, pemutil.WithFilename(rootCertFile)); err != nil {
		t.Fatalf("Failed serializing root certificate: %v", err)
	}
	intermediateCertFile := filepath.Join(dir, "intermediate.pem")
	if _, err = pemutil.Serialize(firstIntermediate, pemutil.WithFilename(intermediateCertFile)); err != nil {
		t.Fatalf("Failed serializing intermediate certificate: %v", err)
	}
	intermediateKeyFile := filepath.Join(dir, "intermediate.key")
	if _, err = pemutil.Serialize(firstIntermediateSigner, pemutil.WithFilename(intermediateKeyFile)); err != nil {
		t.Fatalf("Failed serializing intermediate key: %v", err)
	}

	var intermediateChainContents []byte
	intermediateChain := []*x509.Certificate{secondIntermediate, firstIntermediate}
	for _, cert := range intermediateChain {
		b, err := pemutil.Serialize(cert)
		if err != nil {
			t.Fatalf("Failed serializing intermediate certificate: %v", err)
		}
		intermediateChainContents = append(intermediateChainContents, pem.EncodeToMemory(b)...)
	}
	intermediateChainFile := filepath.Join(dir, "intermediates.pem")
	if err := os.WriteFile(intermediateChainFile, intermediateChainContents, 0644); err != nil {
		t.Fatalf("Failed writing intermediate chain: %v", err)
	}
	intermediateChainKeyFile := filepath.Join(dir, "intermediates.key")
	if _, err = pemutil.Serialize(secondIntermediateSigner, pemutil.WithFilename(intermediateChainKeyFile)); err != nil {
		t.Fatalf("Failed serializing intermediate key: %v", err)
	}

	signer, err := keyutil.GenerateDefaultSigner()
	if err != nil {
		t.Fatalf("Failed creating signer: %v", err)
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "test"},
	}, signer)
	if err != nil {
		t.Fatalf("Failed creating CSR: %v", err)
	}

	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		t.Fatalf("Failed parsing CSR: %v", err)
	}

	t.Run("generated-with-defaults", func(t *testing.T) {
		caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
		t.Cleanup(cancel)
		logger := zap.NewNop()

		ca := &caddypki.CA{
			StorageRaw: []byte(fmt.Sprintf(`{"module": "file_system", "root": %q}`, storageDir)),
		}
		if err := ca.Provision(caddyCtx, "local-test-generated", logger); err != nil {
			t.Fatalf("Failed provisioning CA: %v", err)
		}

		iss := InternalIssuer{
			SignWithRoot: false,
			ca:           ca,
			logger:       logger,
		}

		c, err := iss.Issue(t.Context(), csr)
		if err != nil {
			t.Fatalf("Failed issuing certificate: %v", err)
		}

		chain, err := pemutil.ParseCertificateBundle(c.Certificate)
		if err != nil {
			t.Errorf("Failed issuing certificate: %v", err)
		}
		if len(chain) != 2 {
			t.Errorf("Expected 2 certificates in chain; got %d", len(chain))
		}
	})

	t.Run("single-intermediate-from-disk", func(t *testing.T) {
		caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
		t.Cleanup(cancel)
		logger := zap.NewNop()

		ca := &caddypki.CA{
			Root: &caddypki.KeyPair{
				Certificate: rootCertFile,
			},
			Intermediate: &caddypki.KeyPair{
				Certificate: intermediateCertFile,
				PrivateKey:  intermediateKeyFile,
			},
			StorageRaw: []byte(fmt.Sprintf(`{"module": "file_system", "root": %q}`, storageDir)),
		}

		if err := ca.Provision(caddyCtx, "local-test-single-intermediate", logger); err != nil {
			t.Fatalf("Failed provisioning CA: %v", err)
		}

		iss := InternalIssuer{
			ca:           ca,
			SignWithRoot: false,
			logger:       logger,
		}

		c, err := iss.Issue(t.Context(), csr)
		if err != nil {
			t.Fatalf("Failed issuing certificate: %v", err)
		}

		chain, err := pemutil.ParseCertificateBundle(c.Certificate)
		if err != nil {
			t.Errorf("Failed issuing certificate: %v", err)
		}
		if len(chain) != 2 {
			t.Errorf("Expected 2 certificates in chain; got %d", len(chain))
		}
	})

	t.Run("multiple-intermediates-from-disk", func(t *testing.T) {
		caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
		t.Cleanup(cancel)
		logger := zap.NewNop()

		ca := &caddypki.CA{
			Root: &caddypki.KeyPair{
				Certificate: rootCertFile,
			},
			Intermediate: &caddypki.KeyPair{
				Certificate: intermediateChainFile,
				PrivateKey:  intermediateChainKeyFile,
			},
			StorageRaw: []byte(fmt.Sprintf(`{"module": "file_system", "root": %q}`, storageDir)),
		}

		if err := ca.Provision(caddyCtx, "local-test", zap.NewNop()); err != nil {
			t.Fatalf("Failed provisioning CA: %v", err)
		}

		iss := InternalIssuer{
			ca:           ca,
			SignWithRoot: false,
			logger:       logger,
		}

		c, err := iss.Issue(t.Context(), csr)
		if err != nil {
			t.Fatalf("Failed issuing certificate: %v", err)
		}

		chain, err := pemutil.ParseCertificateBundle(c.Certificate)
		if err != nil {
			t.Errorf("Failed issuing certificate: %v", err)
		}
		if len(chain) != 3 {
			t.Errorf("Expected 3 certificates in chain; got %d", len(chain))
		}
	})
}
