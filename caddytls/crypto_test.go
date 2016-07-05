package caddytls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"os"
	"runtime"
	"testing"
	"time"
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
	return bytes.Equal(PrivateKeyBytes(a), PrivateKeyBytes(b))
}

// PrivateKeyBytes returns the bytes of DER-encoded key.
func PrivateKeyBytes(key crypto.PrivateKey) []byte {
	var keyBytes []byte
	switch key := key.(type) {
	case *rsa.PrivateKey:
		keyBytes = x509.MarshalPKCS1PrivateKey(key)
	case *ecdsa.PrivateKey:
		keyBytes, _ = x509.MarshalECPrivateKey(key)
	}
	return keyBytes
}

func TestStandaloneTLSTicketKeyRotation(t *testing.T) {
	tlsGovChan := make(chan struct{})
	defer close(tlsGovChan)
	callSync := make(chan bool, 1)
	defer close(callSync)

	oldHook := setSessionTicketKeysTestHook
	defer func() {
		setSessionTicketKeysTestHook = oldHook
	}()
	var keysInUse [][32]byte
	setSessionTicketKeysTestHook = func(keys [][32]byte) [][32]byte {
		keysInUse = keys
		callSync <- true
		return keys
	}

	c := new(tls.Config)
	timer := time.NewTicker(time.Millisecond * 1)

	go standaloneTLSTicketKeyRotation(c, timer, tlsGovChan)

	rounds := 0
	var lastTicketKey [32]byte
	for {
		select {
		case <-callSync:
			if lastTicketKey == keysInUse[0] {
				close(tlsGovChan)
				t.Errorf("The same TLS ticket key has been used again (not rotated): %x.", lastTicketKey)
				return
			}
			lastTicketKey = keysInUse[0]
			rounds++
			if rounds <= NumTickets && len(keysInUse) != rounds {
				close(tlsGovChan)
				t.Errorf("Expected TLS ticket keys in use: %d; Got instead: %d.", rounds, len(keysInUse))
				return
			}
			if c.SessionTicketsDisabled == true {
				t.Error("Session tickets have been disabled unexpectedly.")
				return
			}
			if rounds >= NumTickets+1 {
				return
			}
		case <-time.After(time.Second * 1):
			t.Errorf("Timeout after %d rounds.", rounds)
			return
		}
	}
}
