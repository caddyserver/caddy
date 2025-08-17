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
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"

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

// Compare compares passwords.
func (Argon2idHash) Compare(hashed, plaintext []byte) (bool, error) {
	err := bcrypt.CompareHashAndPassword(hashed, plaintext)
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
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


// FakeHash returns a fake hash.
func (Argon2idHash) FakeHash() []byte {
	// hashed with the following command:
	// caddy hash-password --plaintext "antitiming" --algorithm "bcrypt"
	return []byte("$2a$14$X3ulqf/iGxnf1k6oMZ.RZeJUoqI9PX2PM4rS5lkIKJXduLGXGPrt6")
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
