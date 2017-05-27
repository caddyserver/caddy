// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// Package chacha20 implements the ChaCha20 / XChaCha20 stream chipher.
// Notice that one specific key-nonce combination must be unique for all time.
//
// There are three versions of ChaCha20:
// - ChaCha20 with a 64 bit nonce (en/decrypt up to 2^64 * 64 bytes for one key-nonce combination)
// - ChaCha20 with a 96 bit nonce (en/decrypt up to 2^32 * 64 bytes (~256 GB) for one key-nonce combination)
// - XChaCha20 with a 192 bit nonce (en/decrypt up to 2^64 * 64 bytes for one key-nonce combination)
package chacha20 // import "github.com/aead/chacha20"

import (
	"crypto/cipher"

	"github.com/aead/chacha20/chacha"
)

// XORKeyStream crypts bytes from src to dst using the given nonce and key.
// The length of the nonce determinds the version of ChaCha20:
// - 8 bytes:  ChaCha20 with a 64 bit nonce and a 2^64 * 64 byte period.
// - 12 bytes: ChaCha20 as defined in RFC 7539 and a 2^32 * 64 byte period.
// - 24 bytes: XChaCha20 with a 192 bit nonce and a 2^64 * 64 byte period.
// Src and dst may be the same slice but otherwise should not overlap.
// If len(dst) < len(src) this function panics.
// If the nonce is neither 64, 96 nor 192 bits long, this function panics.
func XORKeyStream(dst, src, nonce, key []byte) {
	chacha.XORKeyStream(dst, src, nonce, key, 20)
}

// NewCipher returns a new cipher.Stream implementing a ChaCha20 version.
// The nonce must be unique for one key for all time.
// The length of the nonce determinds the version of ChaCha20:
// - 8 bytes:  ChaCha20 with a 64 bit nonce and a 2^64 * 64 byte period.
// - 12 bytes: ChaCha20 as defined in RFC 7539 and a 2^32 * 64 byte period.
// - 24 bytes: XChaCha20 with a 192 bit nonce and a 2^64 * 64 byte period.
// If the nonce is neither 64, 96 nor 192 bits long, a non-nil error is returned.
func NewCipher(nonce, key []byte) (cipher.Stream, error) {
	return chacha.NewCipher(nonce, key, 20)
}
