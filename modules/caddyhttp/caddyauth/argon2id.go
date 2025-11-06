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

const (
	argon2idName           = "argon2id"
	defaultArgon2idTime    = 1
	defaultArgon2idMemory  = 46 * 1024
	defaultArgon2idThreads = 1
	defaultArgon2idKeylen  = 32
	defaultSaltLength      = 16
)

// Argon2idHash implements the Argon2id password hashing.
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
	argHash, storedKey, err := DecodeHash(hashed)
	if err != nil {
		return false, err
	}

	computedKey := argon2.IDKey(
		plaintext,
		argHash.salt,
		argHash.time,
		argHash.memory,
		argHash.threads,
		argHash.keyLen,
	)

	return subtle.ConstantTimeCompare(storedKey, computedKey) == 1, nil
}

// Hash generates an Argon2id hash of the given plaintext using the configured parameters and salt.
func (b Argon2idHash) Hash(plaintext []byte) ([]byte, error) {
	if b.salt == nil {
		s, err := generateSalt(defaultSaltLength)
		if err != nil {
			return nil, err
		}
		b.salt = s
	}

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

// DecodeHash parses an Argon2id PHC string into an Argon2idHash struct and returns the struct along with the derived key.
func DecodeHash(hash []byte) (*Argon2idHash, []byte, error) {
	parts := strings.Split(string(hash), "$")
	if len(parts) != 6 {
		return nil, nil, fmt.Errorf("invalid hash format")
	}

	if parts[1] != argon2idName {
		return nil, nil, fmt.Errorf("unsupported variant: %s", parts[1])
	}

	version, err := strconv.Atoi(strings.TrimPrefix(parts[2], "v="))
	if err != nil {
		return nil, nil, fmt.Errorf("invalid version: %w", err)
	}
	if version != argon2.Version {
		return nil, nil, fmt.Errorf("incompatible version: %d", version)
	}

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

	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil {
		return nil, nil, fmt.Errorf("decode salt: %w", err)
	}

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

// FakeHash returns a constant fake hash for timing attacks mitigation.
func (Argon2idHash) FakeHash() []byte {
	// hashed with the following command:
	// caddy hash-password --plaintext "antitiming" --algorithm "argon2id"
	return []byte("$argon2id$v=19$m=47104,t=1,p=1$P2nzckEdTZ3bxCiBCkRTyA$xQL3Z32eo5jKl7u5tcIsnEKObYiyNZQQf5/4sAau6Pg")
}

// Interface guards
var (
	_ Comparer = (*Argon2idHash)(nil)
	_ Hasher   = (*Argon2idHash)(nil)
)

func generateSalt(length int) ([]byte, error) {
	salt := make([]byte, length)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return salt, nil
}
