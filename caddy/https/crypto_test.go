package https

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"os"
	"runtime"
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
	loadedKey, err := loadRSAPrivateKey(keyFile)
	if err != nil {
		t.Error("error loading private key:", err)
	}

	// verify loaded key is correct
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
