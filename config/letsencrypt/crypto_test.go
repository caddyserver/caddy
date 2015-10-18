package letsencrypt

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
)

func TestSaveAndLoadRSAPrivateKey(t *testing.T) {
	keyFile := "test.key"
	defer os.Remove(keyFile)

	privateKey, err := rsa.GenerateKey(rand.Reader, 256) // small key size is OK for testing
	if err != nil {
		t.Fatal(err)
	}
	privateKeyPEM := pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}

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
	loadedKeyPEM := pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(loadedKey)}

	// very loaded key is correct
	if !bytes.Equal(loadedKeyPEM.Bytes, privateKeyPEM.Bytes) {
		t.Error("Expected key bytes to be the same, but they weren't")
	}
}
