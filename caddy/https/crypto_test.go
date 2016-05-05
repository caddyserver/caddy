package https

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"os"
	"runtime"
	"testing"
)

func TestSaveAndLoadRSAPrivateKey(t *testing.T) {
	keyFile := "test.key"
	defer os.Remove(keyFile)

	privateKey, err := rsa.GenerateKey(rand.Reader, 128) // make tests faster; small key size OK for testing
	if err != nil {
		t.Fatal(err)
	}

	// test save
	err = savePrivateKey(privateKey, keyFile)
	if err != nil {
		t.Fatal("error saving private key:", err)
	}

	// it doesn't make sense to test file permission on windows
	if runtime.GOOS != "windows" {
		// get info of the key file
		info, err := os.Stat(keyFile)
		if err != nil {
			t.Fatal("error stating private key:", err)
		}
		// verify permission of key file is correct
		if info.Mode().Perm() != 0600 {
			t.Error("Expected key file to have permission 0600, but it wasn't")
		}
	}

	// test load
	loadedKey, err := loadPrivateKey(keyFile)
	if err != nil {
		t.Error("error loading private key:", err)
	}

	// verify loaded key is correct
	if !PrivateKeysSame(privateKey, loadedKey) {
		t.Error("Expected key bytes to be the same, but they weren't")
	}
}

func TestSaveAndLoadECCPrivateKey(t *testing.T) {
	keyFile := "test.key"
	defer os.Remove(keyFile)

	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// test save
	err = savePrivateKey(privateKey, keyFile)
	if err != nil {
		t.Fatal("error saving private key:", err)
	}

	// it doesn't make sense to test file permission on windows
	if runtime.GOOS != "windows" {
		// get info of the key file
		info, err := os.Stat(keyFile)
		if err != nil {
			t.Fatal("error stating private key:", err)
		}
		// verify permission of key file is correct
		if info.Mode().Perm() != 0600 {
			t.Error("Expected key file to have permission 0600, but it wasn't")
		}
	}

	// test load
	loadedKey, err := loadPrivateKey(keyFile)
	if err != nil {
		t.Error("error loading private key:", err)
	}

	// verify loaded key is correct
	if !PrivateKeysSame(privateKey, loadedKey) {
		t.Error("Expected key bytes to be the same, but they weren't")
	}
}

// PrivateKeysSame compares the bytes of a and b and returns true if they are the same.
func PrivateKeysSame(a, b crypto.PrivateKey) bool {
	var abytes, bbytes []byte
	var err error

	if abytes, err = PrivateKeyBytes(a); err != nil {
		return false
	}
	if bbytes, err = PrivateKeyBytes(b); err != nil {
		return false
	}
	return bytes.Equal(abytes, bbytes)
}

// PrivateKeyBytes returns the bytes of DER-encoded key.
func PrivateKeyBytes(key crypto.PrivateKey) ([]byte, error) {
	switch key := key.(type) {
	case *rsa.PrivateKey:
		return x509.MarshalPKCS1PrivateKey(key), nil
	case *ecdsa.PrivateKey:
		return x509.MarshalECPrivateKey(key)
	}
	return nil, errors.New("Unknown private key type")
}
