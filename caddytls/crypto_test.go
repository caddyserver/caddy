// Copyright 2015 Light Code Labs, LLC
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
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"
)

func TestSaveAndLoadRSAPrivateKey(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 128) // make tests faster; small key size OK for testing
	if err != nil {
		t.Fatal(err)
	}

	// test save
	savedBytes, err := savePrivateKey(privateKey)
	if err != nil {
		t.Fatal("error saving private key:", err)
	}

	// test load
	loadedKey, err := loadPrivateKey(savedBytes)
	if err != nil {
		t.Error("error loading private key:", err)
	}

	// verify loaded key is correct
	if !PrivateKeysSame(privateKey, loadedKey) {
		t.Error("Expected key bytes to be the same, but they weren't")
	}
}

func TestSaveAndLoadECCPrivateKey(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// test save
	savedBytes, err := savePrivateKey(privateKey)
	if err != nil {
		t.Fatal("error saving private key:", err)
	}

	// test load
	loadedKey, err := loadPrivateKey(savedBytes)
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
	type syncPkt struct {
		ticketKey [32]byte
		keysInUse int
	}

	tlsGovChan := make(chan struct{})
	defer close(tlsGovChan)
	callSync := make(chan syncPkt)

	setSessionTicketKeysTestHookMu.Lock()
	oldHook := setSessionTicketKeysTestHook
	defer func() {
		setSessionTicketKeysTestHookMu.Lock()
		setSessionTicketKeysTestHook = oldHook
		setSessionTicketKeysTestHookMu.Unlock()
	}()
	setSessionTicketKeysTestHook = func(keys [][32]byte) [][32]byte {
		callSync <- syncPkt{keys[0], len(keys)}
		return keys
	}
	setSessionTicketKeysTestHookMu.Unlock()

	c := new(tls.Config)
	timer := time.NewTicker(time.Millisecond * 1)

	go standaloneTLSTicketKeyRotation(c, timer, tlsGovChan)

	rounds := 0
	var lastTicketKey [32]byte
	for {
		select {
		case pkt := <-callSync:
			if lastTicketKey == pkt.ticketKey {
				close(tlsGovChan)
				t.Errorf("The same TLS ticket key has been used again (not rotated): %x.", lastTicketKey)
				return
			}
			lastTicketKey = pkt.ticketKey
			rounds++
			if rounds <= NumTickets && pkt.keysInUse != rounds {
				close(tlsGovChan)
				t.Errorf("Expected TLS ticket keys in use: %d; Got instead: %d.", rounds, pkt.keysInUse)
				return
			}
			if c.SessionTicketsDisabled {
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
