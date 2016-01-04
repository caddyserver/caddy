package letsencrypt

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"os"
	"testing"
)

func init() {
	rsaKeySizeToUse = 128 // make tests faster; small key size OK for testing
}

func TestSaveAndLoadRSAPrivateKey(t *testing.T) {
	keyFile := "test.key"
	defer os.Remove(keyFile)

	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeySizeToUse)
	if err != nil {
		t.Fatal(err)
	}

	// test save
	err = saveRSAPrivateKey(privateKey, keyFile)
	if err != nil {
		t.Fatal("error saving private key:", err)
	}

	// test load
	loadedKey, err := loadRSAPrivateKey(keyFile)
	if err != nil {
		t.Error("error loading private key:", err)
	}

	// very loaded key is correct
	if !rsaPrivateKeysSame(privateKey, loadedKey) {
		t.Error("Expected key bytes to be the same, but they weren't")
	}
}

// rsaPrivateKeysSame compares the bytes of a and b and returns true if they are the same.
func rsaPrivateKeysSame(a, b *rsa.PrivateKey) bool {
	return bytes.Equal(rsaPrivateKeyBytes(a), rsaPrivateKeyBytes(b))
}

// rsaPrivateKeyBytes returns the bytes of DER-encoded key.
func rsaPrivateKeyBytes(key *rsa.PrivateKey) []byte {
	return x509.MarshalPKCS1PrivateKey(key)
}
