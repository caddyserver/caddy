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
	"crypto/subtle"

	"github.com/caddyserver/caddy/v2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/scrypt"
)

func init() {
	caddy.RegisterModule(BcryptHash{})
	caddy.RegisterModule(ScryptHash{})
}

// BcryptHash implements the bcrypt hash.
type BcryptHash struct{}

// CaddyModule returns the Caddy module information.
func (BcryptHash) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.authentication.hashes.bcrypt",
		New: func() caddy.Module { return new(BcryptHash) },
	}
}

// Compare compares passwords.
func (BcryptHash) Compare(hashed, plaintext, _ []byte) (bool, error) {
	err := bcrypt.CompareHashAndPassword(hashed, plaintext)
	if err == bcrypt.ErrMismatchedHashAndPassword {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// ScryptHash implements the scrypt KDF as a hash.
type ScryptHash struct {
	N         int `json:"N,omitempty"`
	R         int `json:"r,omitempty"`
	P         int `json:"p,omitempty"`
	KeyLength int `json:"key_length,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (ScryptHash) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.authentication.hashes.scrypt",
		New: func() caddy.Module { return new(ScryptHash) },
	}
}

// Provision sets up s.
func (s *ScryptHash) Provision(_ caddy.Context) error {
	s.SetDefaults()
	return nil
}

// SetDefaults sets safe default parameters, but does
// not overwrite existing values. Each default parameter
// is set independently; it does not check to ensure
// that r*p < 2^30. The defaults chosen are those as
// recommended in 2019 by
// https://godoc.org/golang.org/x/crypto/scrypt.
func (s *ScryptHash) SetDefaults() {
	if s.N == 0 {
		s.N = 32768
	}
	if s.R == 0 {
		s.R = 8
	}
	if s.P == 0 {
		s.P = 1
	}
	if s.KeyLength == 0 {
		s.KeyLength = 32
	}
}

// Compare compares passwords.
func (s ScryptHash) Compare(hashed, plaintext, salt []byte) (bool, error) {
	ourHash, err := scrypt.Key(plaintext, salt, s.N, s.R, s.P, s.KeyLength)
	if err != nil {
		return false, err
	}
	if hashesMatch(hashed, ourHash) {
		return true, nil
	}
	return false, nil
}

func hashesMatch(pwdHash1, pwdHash2 []byte) bool {
	return subtle.ConstantTimeCompare(pwdHash1, pwdHash2) == 1
}

// Interface guards
var (
	_ Comparer          = (*BcryptHash)(nil)
	_ Comparer          = (*ScryptHash)(nil)
	_ caddy.Provisioner = (*ScryptHash)(nil)
)
