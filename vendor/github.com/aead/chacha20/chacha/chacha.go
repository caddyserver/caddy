// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// Package chacha implements some low-level functions of the
// ChaCha cipher family.
package chacha // import "github.com/aead/chacha20/chacha"

import (
	"encoding/binary"
	"errors"
	"math"
)

const (
	// NonceSize is the size of the ChaCha20 nonce in bytes.
	NonceSize = 8

	// INonceSize is the size of the IETF-ChaCha20 nonce in bytes.
	INonceSize = 12

	// XNonceSize is the size of the XChaCha20 nonce in bytes.
	XNonceSize = 24

	// KeySize is the size of the key in bytes.
	KeySize = 32
)

var (
	useSSE2  bool
	useSSSE3 bool
	useAVX   bool
	useAVX2  bool
)

var (
	errKeySize      = errors.New("chacha20/chacha: bad key length")
	errInvalidNonce = errors.New("chacha20/chacha: bad nonce length")
)

func setup(state *[64]byte, nonce, key []byte) (err error) {
	if len(key) != KeySize {
		err = errKeySize
		return
	}
	var Nonce [16]byte
	switch len(nonce) {
	case NonceSize:
		copy(Nonce[8:], nonce)
		initialize(state, key, &Nonce)
	case INonceSize:
		copy(Nonce[4:], nonce)
		initialize(state, key, &Nonce)
	case XNonceSize:
		var tmpKey [32]byte
		var hNonce [16]byte

		copy(hNonce[:], nonce[:16])
		copy(tmpKey[:], key)
		HChaCha20(&tmpKey, &hNonce, &tmpKey)
		copy(Nonce[8:], nonce[16:])
		initialize(state, tmpKey[:], &Nonce)

		// BUG(aead): A "good" compiler will remove this (optimizations)
		//			  But using the provided key instead of tmpKey,
		//			  will change the key (-> probably confuses users)
		for i := range tmpKey {
			tmpKey[i] = 0
		}
	default:
		err = errInvalidNonce
	}
	return
}

// XORKeyStream crypts bytes from src to dst using the given nonce and key.
// The length of the nonce determinds the version of ChaCha20:
// - NonceSize:  ChaCha20/r with a 64 bit nonce and a 2^64 * 64 byte period.
// - INonceSize: ChaCha20/r as defined in RFC 7539 and a 2^32 * 64 byte period.
// - XNonceSize: XChaCha20/r with a 192 bit nonce and a 2^64 * 64 byte period.
// The rounds argument specifies the number of rounds performed for keystream
// generation - valid values are 8, 12 or 20. The src and dst may be the same slice
// but otherwise should not overlap. If len(dst) < len(src) this function panics.
// If the nonce is neither 64, 96 nor 192 bits long, this function panics.
func XORKeyStream(dst, src, nonce, key []byte, rounds int) {
	if rounds != 20 && rounds != 12 && rounds != 8 {
		panic("chacha20/chacha: bad number of rounds")
	}
	if len(dst) < len(src) {
		panic("chacha20/chacha: dst buffer is to small")
	}
	if len(nonce) == INonceSize && uint64(len(src)) > (1<<38) {
		panic("chacha20/chacha: src is too large")
	}

	var block, state [64]byte
	if err := setup(&state, nonce, key); err != nil {
		panic(err)
	}
	xorKeyStream(dst, src, &block, &state, rounds)
}

// Cipher implements ChaCha20/r (XChaCha20/r) for a given number of rounds r.
type Cipher struct {
	state, block [64]byte
	off          int
	rounds       int // 20 for ChaCha20
	noncesize    int
}

// NewCipher returns a new *chacha.Cipher implementing the ChaCha20/r or XChaCha20/r
// (r = 8, 12 or 20) stream cipher. The nonce must be unique for one key for all time.
// The length of the nonce determinds the version of ChaCha20:
// - NonceSize:  ChaCha20/r with a 64 bit nonce and a 2^64 * 64 byte period.
// - INonceSize: ChaCha20/r as defined in RFC 7539 and a 2^32 * 64 byte period.
// - XNonceSize: XChaCha20/r with a 192 bit nonce and a 2^64 * 64 byte period.
// If the nonce is neither 64, 96 nor 192 bits long, a non-nil error is returned.
func NewCipher(nonce, key []byte, rounds int) (*Cipher, error) {
	if rounds != 20 && rounds != 12 && rounds != 8 {
		panic("chacha20/chacha: bad number of rounds")
	}

	c := new(Cipher)
	if err := setup(&(c.state), nonce, key); err != nil {
		return nil, err
	}
	c.rounds = rounds

	if len(nonce) == INonceSize {
		c.noncesize = INonceSize
	} else {
		c.noncesize = NonceSize
	}

	return c, nil
}

// XORKeyStream crypts bytes from src to dst. Src and dst may be the same slice
// but otherwise should not overlap. If len(dst) < len(src) the function panics.
func (c *Cipher) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("chacha20/chacha: dst buffer is to small")
	}

	if c.off > 0 {
		n := len(c.block[c.off:])
		if len(src) <= n {
			for i, v := range src {
				dst[i] = v ^ c.block[c.off]
				c.off++
			}
			if c.off == 64 {
				c.off = 0
			}
			return
		}

		for i, v := range c.block[c.off:] {
			dst[i] = src[i] ^ v
		}
		src = src[n:]
		dst = dst[n:]
		c.off = 0
	}

	// check for counter overflow
	blocksToXOR := len(src) / 64
	if len(src)%64 != 0 {
		blocksToXOR++
	}
	var overflow bool
	if c.noncesize == INonceSize {
		overflow = binary.LittleEndian.Uint32(c.state[48:]) > math.MaxUint32-uint32(blocksToXOR)
	} else {
		overflow = binary.LittleEndian.Uint64(c.state[48:]) > math.MaxUint64-uint64(blocksToXOR)
	}
	if overflow {
		panic("chacha20/chacha: counter overflow")
	}

	c.off += xorKeyStream(dst, src, &(c.block), &(c.state), c.rounds)
}

// SetCounter skips ctr * 64 byte blocks. SetCounter(0) resets the cipher.
// This function always skips the unused keystream of the current 64 byte block.
func (c *Cipher) SetCounter(ctr uint64) {
	if c.noncesize == INonceSize {
		binary.LittleEndian.PutUint32(c.state[48:], uint32(ctr))
	} else {
		binary.LittleEndian.PutUint64(c.state[48:], ctr)
	}
	c.off = 0
}

// HChaCha20 generates 32 pseudo-random bytes from a 128 bit nonce and a 256 bit secret key.
// It can be used as a key-derivation-function (KDF).
func HChaCha20(out *[32]byte, nonce *[16]byte, key *[32]byte) { hChaCha20(out, nonce, key) }
