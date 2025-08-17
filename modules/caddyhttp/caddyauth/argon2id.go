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

package caddyauth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(Argon2idHash{})
}

// Argon2idHash implements the argon2id hash.
type Argon2idHash struct {
	salt    []byte
	time    uint32
	memory  uint32
	threads uint8
	keyLen  uint32
}

// CaddyModule returns the Caddy module information.
func (Argon2idHash) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.authentication.hashes.argon2id",
		New: func() caddy.Module { return new(Argon2idHash) },
	}
}

// Compare checks if the plaintext password matches the given Argon2id hash.
func (Argon2idHash) Compare(hashed, plaintext []byte) (bool, error) {
	// Decode the stored hash
	argHash, storedKey, err := DecodeHash(hashed)
	if err != nil {
		return false, err
	}

	// Re-hash the plaintext with the same parameters and salt
	computedHash, err := argHash.Hash(plaintext)
	if err != nil {
		return false, err
	}

	_, computedKey, err := DecodeHash(computedHash)
	if err != nil {
		return false, err
	}

	// Use constant-time comparison for security
	if subtle.ConstantTimeCompare(storedKey, computedKey) == 1 {
		return true, nil
	}
	return false, nil
}

// Hash generates an Argon2id hash of the given plaintext using the configured parameters and salt.
func (b Argon2idHash) Hash(plaintext []byte) ([]byte, error) {
	key := argon2.IDKey(
		plaintext,
		b.salt,
		b.time,
		b.memory,
		b.threads,
		b.keyLen,
	)

	hash := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		b.memory,
		b.time,
		b.threads,
		base64.RawStdEncoding.EncodeToString(b.salt),
		base64.RawStdEncoding.EncodeToString(key),
	)

	return []byte(hash), nil
}

// DecodeHash parses an Argon2id PHC string into an Argon2idHash struct
// and returns the struct along with the derived key.
// Format: $argon2id$v=19$m=<memory>,t=<iterations>,p=<parallelism>$<salt>$<hash>
func DecodeHash(hash []byte) (*Argon2idHash, []byte, error) {
	parts := strings.Split(string(hash), "$")
	if len(parts) != 6 {
		return nil, nil, fmt.Errorf("invalid hash format")
	}

	if parts[1] != "argon2id" {
		return nil, nil, fmt.Errorf("unsupported variant: %s", parts[1])
	}

	// Version
	version, err := strconv.Atoi(strings.TrimPrefix(parts[2], "v="))
	if err != nil {
		return nil, nil, fmt.Errorf("invalid version: %w", err)
	}
	if version != argon2.Version {
		return nil, nil, fmt.Errorf("incompatible version: %d", version)
	}

	// Parameters
	params := strings.Split(parts[3], ",")
	if len(params) != 3 {
		return nil, nil, fmt.Errorf("invalid parameters")
	}

	mem, err := strconv.ParseUint(strings.TrimPrefix(params[0], "m="), 10, 32)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid memory parameter: %w", err)
	}

	iter, err := strconv.ParseUint(strings.TrimPrefix(params[1], "t="), 10, 32)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid iterations parameter: %w", err)
	}

	threads, err := strconv.ParseUint(strings.TrimPrefix(params[2], "p="), 10, 8)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid parallelism parameter: %w", err)
	}

	// Salt
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil {
		return nil, nil, fmt.Errorf("decode salt: %w", err)
	}

	// Key
	key, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil {
		return nil, nil, fmt.Errorf("decode key: %w", err)
	}

	return &Argon2idHash{
		salt:    salt,
		time:    uint32(iter),
		memory:  uint32(mem),
		threads: uint8(threads),
		keyLen:  uint32(len(key)),
	}, key, nil
}

// FakeHash returns a fake hash.
func (Argon2idHash) FakeHash() []byte {
	// hashed with the following command:
	// caddy hash-password --plaintext "antitiming" --algorithm "argon2id"
	return []byte("$argon2id$v=19$m=47104,t=1,p=1$OAdQWX6By8ZZqB0vuW8pmQ$go5ZgOWvTOS5zhJmOrXEhV4LAnxBXUFwc/KVJfy2X4k")
}

// Interface guards
var (
	_ Comparer = (*Argon2idHash)(nil)
	_ Hasher   = (*Argon2idHash)(nil)
)

func generateSalt(length int) ([]byte, error) {
	salt := make([]byte, length)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}
