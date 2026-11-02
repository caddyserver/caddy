package caddypki

import (
	"crypto/x509"
	"testing"
	"time"

	"go.step.sm/crypto/x509util"
)

func TestGenerateRoot(t *testing.T) {
	root, signer, err := generateRoot("Test Root CA")
	if err != nil {
		t.Fatalf("generateRoot() error: %v", err)
	}
	if root == nil {
		t.Fatal("root cert is nil")
	}
	if signer == nil {
		t.Fatal("signer is nil")
	}

	// Check common name
	if root.Subject.CommonName != "Test Root CA" {
		t.Errorf("Subject.CommonName = %q, want 'Test Root CA'", root.Subject.CommonName)
	}

	// Root should be self-signed (issuer == subject)
	if root.Issuer.CommonName != root.Subject.CommonName {
		t.Errorf("root cert should be self-signed: issuer CN = %q, subject CN = %q",
			root.Issuer.CommonName, root.Subject.CommonName)
	}

	// Should be a CA
	if !root.IsCA {
		t.Error("root cert should be a CA")
	}

	// Check validity period is approximately defaultRootLifetime
	notBefore := root.NotBefore
	notAfter := root.NotAfter
	duration := notAfter.Sub(notBefore)
	expected := defaultRootLifetime
	// Allow a small tolerance
	if duration < expected-time.Hour || duration > expected+time.Hour {
		t.Errorf("validity duration = %v, want approximately %v", duration, expected)
	}

	// Check key usage
	if root.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("root cert should have KeyUsageCertSign")
	}
}

func TestGenerateRootEmptyCommonName(t *testing.T) {
	root, _, err := generateRoot("")
	if err != nil {
		t.Fatalf("generateRoot() with empty CN error: %v", err)
	}
	if root.Subject.CommonName != "" {
		t.Errorf("Subject.CommonName = %q, want empty", root.Subject.CommonName)
	}
}

func TestGenerateIntermediate(t *testing.T) {
	// First generate a root
	root, rootKey, err := generateRoot("Test Root CA")
	if err != nil {
		t.Fatalf("generateRoot() error: %v", err)
	}

	// Generate intermediate signed by root
	lifetime := 7 * 24 * time.Hour
	intermediate, intSigner, err := generateIntermediate("Test Intermediate CA", root, rootKey, lifetime)
	if err != nil {
		t.Fatalf("generateIntermediate() error: %v", err)
	}
	if intermediate == nil {
		t.Fatal("intermediate cert is nil")
	}
	if intSigner == nil {
		t.Fatal("intermediate signer is nil")
	}

	// Check common name
	if intermediate.Subject.CommonName != "Test Intermediate CA" {
		t.Errorf("Subject.CommonName = %q, want 'Test Intermediate CA'", intermediate.Subject.CommonName)
	}

	// Intermediate should be signed by root (issuer == root subject)
	if intermediate.Issuer.CommonName != root.Subject.CommonName {
		t.Errorf("intermediate issuer CN = %q, want root CN %q",
			intermediate.Issuer.CommonName, root.Subject.CommonName)
	}

	// Should be a CA
	if !intermediate.IsCA {
		t.Error("intermediate cert should be a CA")
	}

	// Check validity period
	duration := intermediate.NotAfter.Sub(intermediate.NotBefore)
	if duration < lifetime-time.Hour || duration > lifetime+time.Hour {
		t.Errorf("validity duration = %v, want approximately %v", duration, lifetime)
	}

	// Verify intermediate is actually signed by the root
	pool := x509.NewCertPool()
	pool.AddCert(root)
	_, err = intermediate.Verify(x509.VerifyOptions{
		Roots: pool,
	})
	if err != nil {
		t.Errorf("intermediate cert verification against root failed: %v", err)
	}
}

func TestGenerateIntermediateDifferentKey(t *testing.T) {
	root, rootKey, err := generateRoot("Root CA")
	if err != nil {
		t.Fatalf("generateRoot() error: %v", err)
	}

	int1, signer1, err := generateIntermediate("Int 1", root, rootKey, 24*time.Hour)
	if err != nil {
		t.Fatalf("first generateIntermediate() error: %v", err)
	}
	int2, signer2, err := generateIntermediate("Int 2", root, rootKey, 24*time.Hour)
	if err != nil {
		t.Fatalf("second generateIntermediate() error: %v", err)
	}

	// Different intermediates should have different keys
	_ = int1
	_ = int2
	pub1 := signer1.Public()
	pub2 := signer2.Public()
	// Keys are random, so they should be different
	if pub1 == pub2 {
		t.Error("two intermediates should have different keys")
	}
}

func TestNewCert(t *testing.T) {
	cert, signer, err := newCert("Test CN", x509util.DefaultRootTemplate, 365*24*time.Hour)
	if err != nil {
		t.Fatalf("newCert() error: %v", err)
	}
	if cert == nil {
		t.Fatal("cert is nil")
	}
	if signer == nil {
		t.Fatal("signer is nil")
	}
	if cert.Subject.CommonName != "Test CN" {
		t.Errorf("Subject.CommonName = %q, want 'Test CN'", cert.Subject.CommonName)
	}

	// NotBefore should be approximately now
	if time.Since(cert.NotBefore) > time.Minute {
		t.Errorf("NotBefore = %v, expected to be within a minute of now", cert.NotBefore)
	}

	// NotAfter should be approximately NotBefore + lifetime
	expectedNotAfter := cert.NotBefore.Add(365 * 24 * time.Hour)
	if cert.NotAfter.Sub(expectedNotAfter) > time.Second {
		t.Errorf("NotAfter = %v, expected %v", cert.NotAfter, expectedNotAfter)
	}
}
