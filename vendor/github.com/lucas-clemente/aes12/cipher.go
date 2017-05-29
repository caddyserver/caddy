// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package aes12

import "strconv"

// The AES block size in bytes.
const BlockSize = 16

// A cipher is an instance of AES encryption using a particular key.
type aesCipher struct {
	enc []uint32
	dec []uint32
}

type KeySizeError int

func (k KeySizeError) Error() string {
	return "crypto/aes: invalid key size " + strconv.Itoa(int(k))
}

// NewCipher creates and returns a new Block.
// The key argument should be the AES key,
// either 16, 24, or 32 bytes to select
// AES-128, AES-192, or AES-256.
func NewCipher(key []byte) (Block, error) {
	k := len(key)
	switch k {
	default:
		return nil, KeySizeError(k)
	case 16, 24, 32:
		break
	}
	return newCipher(key)
}

// newCipherGeneric creates and returns a new Block
// implemented in pure Go.
func newCipherGeneric(key []byte) (Block, error) {
	n := len(key) + 28
	c := aesCipher{make([]uint32, n), make([]uint32, n)}
	expandKeyGo(key, c.enc, c.dec)
	return &c, nil
}

func (c *aesCipher) BlockSize() int { return BlockSize }

func (c *aesCipher) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("crypto/aes: input not full block")
	}
	if len(dst) < BlockSize {
		panic("crypto/aes: output not full block")
	}
	encryptBlockGo(c.enc, dst, src)
}

func (c *aesCipher) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("crypto/aes: input not full block")
	}
	if len(dst) < BlockSize {
		panic("crypto/aes: output not full block")
	}
	decryptBlockGo(c.dec, dst, src)
}
