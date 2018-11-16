// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// +build 386,!gccgo,!appengine,!nacl

package chacha

import (
	"encoding/binary"

	"golang.org/x/sys/cpu"
)

func init() {
	useSSE2 = cpu.X86.HasSSE2
	useSSSE3 = cpu.X86.HasSSSE3
	useAVX = false
	useAVX2 = false
}

func initialize(state *[64]byte, key []byte, nonce *[16]byte) {
	binary.LittleEndian.PutUint32(state[0:], sigma[0])
	binary.LittleEndian.PutUint32(state[4:], sigma[1])
	binary.LittleEndian.PutUint32(state[8:], sigma[2])
	binary.LittleEndian.PutUint32(state[12:], sigma[3])
	copy(state[16:], key[:])
	copy(state[48:], nonce[:])
}

// This function is implemented in chacha_386.s
//go:noescape
func hChaCha20SSE2(out *[32]byte, nonce *[16]byte, key *[32]byte)

// This function is implemented in chacha_386.s
//go:noescape
func hChaCha20SSSE3(out *[32]byte, nonce *[16]byte, key *[32]byte)

// This function is implemented in chacha_386.s
//go:noescape
func xorKeyStreamSSE2(dst, src []byte, block, state *[64]byte, rounds int) int

func hChaCha20(out *[32]byte, nonce *[16]byte, key *[32]byte) {
	switch {
	case useSSSE3:
		hChaCha20SSSE3(out, nonce, key)
	case useSSE2:
		hChaCha20SSE2(out, nonce, key)
	default:
		hChaCha20Generic(out, nonce, key)
	}
}

func xorKeyStream(dst, src []byte, block, state *[64]byte, rounds int) int {
	if useSSE2 {
		return xorKeyStreamSSE2(dst, src, block, state, rounds)
	} else {
		return xorKeyStreamGeneric(dst, src, block, state, rounds)
	}
}
