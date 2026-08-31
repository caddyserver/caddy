package caddyauth

import (
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestArgon2idHashCaddyModule(t *testing.T) {
	a := Argon2idHash{}
	info := a.CaddyModule()
	if info.ID != "http.authentication.hashes.argon2id" {
		t.Errorf("CaddyModule().ID = %v, want 'http.authentication.hashes.argon2id'", info.ID)
	}
}

func TestArgon2idDecodeHash(t *testing.T) {
	tests := []struct {
		name       string
		hash       string
		wantErr    bool
		wantErrStr string
	}{
		{
			name: "valid hash",
			hash: "$argon2id$v=19$m=47104,t=1,p=1$P2nzckEdTZ3bxCiBCkRTyA$xQL3Z32eo5jKl7u5tcIsnEKObYiyNZQQf5/4sAau6Pg",
		},
		{
			name:    "too few parts",
			hash:    "$argon2id$v=19$m=47104,t=1,p=1",
			wantErr: true,
		},
		{
			name:       "wrong variant",
			hash:       "$argon2i$v=19$m=47104,t=1,p=1$c29tZXNhbHQ$c29tZWtleQ",
			wantErr:    true,
			wantErrStr: "unsupported variant",
		},
		{
			name:    "invalid version",
			hash:    "$argon2id$v=abc$m=47104,t=1,p=1$c29tZXNhbHQ$c29tZWtleQ",
			wantErr: true,
		},
		{
			name:    "incompatible version",
			hash:    "$argon2id$v=18$m=47104,t=1,p=1$c29tZXNhbHQ$c29tZWtleQ",
			wantErr: true,
		},
		{
			name:    "invalid parameters - too few",
			hash:    "$argon2id$v=19$m=47104,t=1$c29tZXNhbHQ$c29tZWtleQ",
			wantErr: true,
		},
		{
			name:    "invalid memory parameter",
			hash:    "$argon2id$v=19$m=abc,t=1,p=1$c29tZXNhbHQ$c29tZWtleQ",
			wantErr: true,
		},
		{
			name:    "invalid iterations parameter",
			hash:    "$argon2id$v=19$m=47104,t=abc,p=1$c29tZXNhbHQ$c29tZWtleQ",
			wantErr: true,
		},
		{
			name:    "invalid parallelism parameter",
			hash:    "$argon2id$v=19$m=47104,t=1,p=abc$c29tZXNhbHQ$c29tZWtleQ",
			wantErr: true,
		},
		{
			name:    "invalid salt base64",
			hash:    "$argon2id$v=19$m=47104,t=1,p=1$!!!invalid!!!$c29tZWtleQ",
			wantErr: true,
		},
		{
			name:    "invalid key base64",
			hash:    "$argon2id$v=19$m=47104,t=1,p=1$c29tZXNhbHQ$!!!invalid!!!",
			wantErr: true,
		},
		{
			name:    "empty string",
			hash:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			argHash, key, err := DecodeHash([]byte(tt.hash))
			if tt.wantErr {
				if err == nil {
					t.Error("DecodeHash() should return error")
				}
				if tt.wantErrStr != "" && !strings.Contains(err.Error(), tt.wantErrStr) {
					t.Errorf("error %q should contain %q", err.Error(), tt.wantErrStr)
				}
				return
			}
			if err != nil {
				t.Fatalf("DecodeHash() error: %v", err)
			}
			if argHash == nil {
				t.Fatal("DecodeHash() returned nil hash")
			}
			if key == nil {
				t.Fatal("DecodeHash() returned nil key")
			}
			if argHash.time == 0 {
				t.Error("decoded time is 0")
			}
			if argHash.memory == 0 {
				t.Error("decoded memory is 0")
			}
			if argHash.threads == 0 {
				t.Error("decoded threads is 0")
			}
			if len(argHash.salt) == 0 {
				t.Error("decoded salt is empty")
			}
		})
	}
}

func TestArgon2idDecodeHashParsesCorrectValues(t *testing.T) {
	hash := "$argon2id$v=19$m=47104,t=1,p=1$P2nzckEdTZ3bxCiBCkRTyA$xQL3Z32eo5jKl7u5tcIsnEKObYiyNZQQf5/4sAau6Pg"
	argHash, _, err := DecodeHash([]byte(hash))
	if err != nil {
		t.Fatalf("DecodeHash() error: %v", err)
	}

	if argHash.memory != 47104 {
		t.Errorf("memory = %d, want 47104", argHash.memory)
	}
	if argHash.time != 1 {
		t.Errorf("time = %d, want 1", argHash.time)
	}
	if argHash.threads != 1 {
		t.Errorf("threads = %d, want 1", argHash.threads)
	}
}

func TestArgon2idCompare(t *testing.T) {
	hasher := Argon2idHash{
		time:    defaultArgon2idTime,
		memory:  defaultArgon2idMemory,
		threads: defaultArgon2idThreads,
		keyLen:  defaultArgon2idKeylen,
	}

	plaintext := []byte("test-password")
	hashed, err := hasher.Hash(plaintext)
	if err != nil {
		t.Fatalf("Hash() error: %v", err)
	}

	tests := []struct {
		name      string
		plaintext []byte
		wantMatch bool
	}{
		{name: "correct password", plaintext: plaintext, wantMatch: true},
		{name: "wrong password", plaintext: []byte("wrong"), wantMatch: false},
		{name: "empty password", plaintext: []byte(""), wantMatch: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, err := hasher.Compare(hashed, tt.plaintext)
			if err != nil {
				t.Fatalf("Compare() error: %v", err)
			}
			if match != tt.wantMatch {
				t.Errorf("Compare() = %v, want %v", match, tt.wantMatch)
			}
		})
	}
}

func TestArgon2idHashRoundTrip(t *testing.T) {
	hasher := Argon2idHash{
		time:    defaultArgon2idTime,
		memory:  defaultArgon2idMemory,
		threads: defaultArgon2idThreads,
		keyLen:  defaultArgon2idKeylen,
	}
	plaintext := []byte("round-trip-test")

	hashed, err := hasher.Hash(plaintext)
	if err != nil {
		t.Fatalf("Hash() error: %v", err)
	}

	// Verify hash format starts with $argon2id$
	if !strings.HasPrefix(string(hashed), "$argon2id$v=") {
		t.Errorf("Hash() output %q doesn't start with '$argon2id$v='", hashed)
	}

	match, err := hasher.Compare(hashed, plaintext)
	if err != nil {
		t.Fatalf("Compare() error: %v", err)
	}
	if !match {
		t.Error("Hash then Compare round-trip failed")
	}
}

func TestArgon2idHashProducesDifferentHashes(t *testing.T) {
	hasher := Argon2idHash{
		time:    defaultArgon2idTime,
		memory:  defaultArgon2idMemory,
		threads: defaultArgon2idThreads,
		keyLen:  defaultArgon2idKeylen,
	}
	plaintext := []byte("same-password")

	hash1, err := hasher.Hash(plaintext)
	if err != nil {
		t.Fatalf("Hash() first error: %v", err)
	}
	hash2, err := hasher.Hash(plaintext)
	if err != nil {
		t.Fatalf("Hash() second error: %v", err)
	}

	// Different salts should produce different hashes
	if string(hash1) == string(hash2) {
		t.Error("Hash() should produce different output on each call (different salt)")
	}

	// But both should verify correctly
	match1, _ := hasher.Compare(hash1, plaintext)
	match2, _ := hasher.Compare(hash2, plaintext)
	if !match1 || !match2 {
		t.Error("Both hashes should verify against original plaintext")
	}
}

func TestArgon2idFakeHash(t *testing.T) {
	hasher := Argon2idHash{}
	fake := hasher.FakeHash()

	if len(fake) == 0 {
		t.Fatal("FakeHash() returned empty result")
	}

	// Should be a valid argon2id hash
	_, _, err := DecodeHash(fake)
	if err != nil {
		t.Errorf("FakeHash() is not a valid argon2id hash: %v", err)
	}

	// Should match the known plaintext "antitiming"
	match, err := hasher.Compare(fake, []byte("antitiming"))
	if err != nil {
		t.Fatalf("Compare() with FakeHash error: %v", err)
	}
	if !match {
		t.Error("FakeHash() should match plaintext 'antitiming'")
	}
}

func TestArgon2idCompareWithInvalidHash(t *testing.T) {
	hasher := Argon2idHash{}
	_, err := hasher.Compare([]byte("not-a-hash"), []byte("password"))
	if err == nil {
		t.Error("Compare() with invalid hash should return error")
	}
}

func TestArgon2idHashVersionInOutput(t *testing.T) {
	hasher := Argon2idHash{
		time:    defaultArgon2idTime,
		memory:  defaultArgon2idMemory,
		threads: defaultArgon2idThreads,
		keyLen:  defaultArgon2idKeylen,
	}

	hashed, err := hasher.Hash([]byte("test"))
	if err != nil {
		t.Fatalf("Hash() error: %v", err)
	}

	// Verify version field matches current argon2 version
	versionStr := "v=" + strings.Split(string(hashed), "$")[2]
	if versionStr != "v=v=19" {
		// argon2.Version is 0x13 = 19
		expectedVersion := "$argon2id$v=19$"
		if !strings.Contains(string(hashed), expectedVersion[:len(expectedVersion)-1]) {
			t.Errorf("Hash output should contain version %d, got %q", argon2.Version, hashed)
		}
	}
}

func TestGenerateSalt(t *testing.T) {
	salt1, err := generateSalt(16)
	if err != nil {
		t.Fatalf("generateSalt(16) error: %v", err)
	}
	if len(salt1) != 16 {
		t.Errorf("generateSalt(16) length = %d, want 16", len(salt1))
	}

	salt2, err := generateSalt(16)
	if err != nil {
		t.Fatalf("generateSalt(16) second call error: %v", err)
	}

	// Two salts should be different (with overwhelming probability)
	if string(salt1) == string(salt2) {
		t.Error("generateSalt() should produce different values on each call")
	}
}

func TestGenerateSaltLengths(t *testing.T) {
	for _, length := range []int{8, 16, 32, 64} {
		salt, err := generateSalt(length)
		if err != nil {
			t.Fatalf("generateSalt(%d) error: %v", length, err)
		}
		if len(salt) != length {
			t.Errorf("generateSalt(%d) length = %d, want %d", length, len(salt), length)
		}
	}
}
