package caddyauth

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestBcryptHashCaddyModule(t *testing.T) {
	b := BcryptHash{}
	info := b.CaddyModule()
	if info.ID != "http.authentication.hashes.bcrypt" {
		t.Errorf("CaddyModule().ID = %v, want 'http.authentication.hashes.bcrypt'", info.ID)
	}
}

func TestBcryptHashCompare(t *testing.T) {
	hasher := BcryptHash{}
	plaintext := []byte("correct-password")
	hashed, err := bcrypt.GenerateFromPassword(plaintext, bcrypt.MinCost)
	if err != nil {
		t.Fatalf("failed to generate bcrypt hash: %v", err)
	}

	tests := []struct {
		name      string
		hashed    []byte
		plaintext []byte
		wantMatch bool
		wantErr   bool
	}{
		{
			name:      "correct password matches",
			hashed:    hashed,
			plaintext: plaintext,
			wantMatch: true,
		},
		{
			name:      "incorrect password does not match",
			hashed:    hashed,
			plaintext: []byte("wrong-password"),
			wantMatch: false,
		},
		{
			name:      "empty password does not match",
			hashed:    hashed,
			plaintext: []byte(""),
			wantMatch: false,
		},
		{
			name:      "invalid hash returns error",
			hashed:    []byte("not-a-bcrypt-hash"),
			plaintext: plaintext,
			wantMatch: false,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, err := hasher.Compare(tt.hashed, tt.plaintext)
			if tt.wantErr {
				if err == nil {
					t.Error("Compare() should return error")
				}
				return
			}
			if err != nil {
				t.Fatalf("Compare() error: %v", err)
			}
			if match != tt.wantMatch {
				t.Errorf("Compare() = %v, want %v", match, tt.wantMatch)
			}
		})
	}
}

func TestBcryptHashHash(t *testing.T) {
	hasher := BcryptHash{}
	plaintext := []byte("test-password")
	hashed, err := hasher.Hash(plaintext)
	if err != nil {
		t.Fatalf("Hash() error: %v", err)
	}
	if len(hashed) == 0 {
		t.Fatal("Hash() returned empty result")
	}

	// Verify the hash is valid bcrypt
	err = bcrypt.CompareHashAndPassword(hashed, plaintext)
	if err != nil {
		t.Errorf("Hash() produced invalid bcrypt hash: %v", err)
	}

	// Verify re-hashing produces different output (different salt)
	hashed2, err := hasher.Hash(plaintext)
	if err != nil {
		t.Fatalf("Hash() second call error: %v", err)
	}
	if string(hashed) == string(hashed2) {
		t.Error("Hash() should produce different output on each call (different salt)")
	}
}

func TestBcryptHashRoundTrip(t *testing.T) {
	hasher := BcryptHash{}
	plaintext := []byte("round-trip-test")
	hashed, err := hasher.Hash(plaintext)
	if err != nil {
		t.Fatalf("Hash() error: %v", err)
	}
	match, err := hasher.Compare(hashed, plaintext)
	if err != nil {
		t.Fatalf("Compare() error: %v", err)
	}
	if !match {
		t.Error("Hash then Compare round-trip failed: password should match")
	}
}

func TestBcryptFakeHash(t *testing.T) {
	hasher := BcryptHash{}
	fake := hasher.FakeHash()
	if len(fake) == 0 {
		t.Fatal("FakeHash() returned empty result")
	}

	// FakeHash should be a valid bcrypt hash matching "antitiming"
	err := bcrypt.CompareHashAndPassword(fake, []byte("antitiming"))
	if err != nil {
		t.Errorf("FakeHash() is not a valid bcrypt hash of 'antitiming': %v", err)
	}

	// Calling FakeHash multiple times should return the same value
	fake2 := hasher.FakeHash()
	if string(fake) != string(fake2) {
		t.Error("FakeHash() should return constant value")
	}
}

func TestBcryptHashWithCustomCost(t *testing.T) {
	hasher := BcryptHash{cost: bcrypt.MinCost}
	plaintext := []byte("low-cost-test")
	hashed, err := hasher.Hash(plaintext)
	if err != nil {
		t.Fatalf("Hash() with MinCost error: %v", err)
	}
	match, err := hasher.Compare(hashed, plaintext)
	if err != nil {
		t.Fatalf("Compare() error: %v", err)
	}
	if !match {
		t.Error("Hash/Compare with MinCost should match")
	}
}
