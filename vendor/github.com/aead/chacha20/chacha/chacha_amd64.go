// Copyright (c) 2017 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// +build go1.7,amd64,!gccgo,!appengine,!nacl

package chacha

import "golang.org/x/sys/cpu"

func init() {
	useSSE2 = cpu.X86.HasSSE2
	useSSSE3 = cpu.X86.HasSSSE3
	useAVX = cpu.X86.HasAVX
	useAVX2 = cpu.X86.HasAVX2
}

// This function is implemented in chacha_amd64.s
//go:noescape
func initialize(state *[64]byte, key []byte, nonce *[16]byte)

// This function is implemented in chacha_amd64.s
//go:noescape
func hChaCha20SSE2(out *[32]byte, nonce *[16]byte, key *[32]byte)

// This function is implemented in chacha_amd64.s
//go:noescape
func hChaCha20SSSE3(out *[32]byte, nonce *[16]byte, key *[32]byte)

// This function is implemented in chachaAVX2_amd64.s
//go:noescape
func hChaCha20AVX(out *[32]byte, nonce *[16]byte, key *[32]byte)

// This function is implemented in chacha_amd64.s
//go:noescape
func xorKeyStreamSSE2(dst, src []byte, block, state *[64]byte, rounds int) int

// This function is implemented in chacha_amd64.s
//go:noescape
func xorKeyStreamSSSE3(dst, src []byte, block, state *[64]byte, rounds int) int

// This function is implemented in chacha_amd64.s
//go:noescape
func xorKeyStreamAVX(dst, src []byte, block, state *[64]byte, rounds int) int

// This function is implemented in chachaAVX2_amd64.s
//go:noescape
func xorKeyStreamAVX2(dst, src []byte, block, state *[64]byte, rounds int) int

func hChaCha20(out *[32]byte, nonce *[16]byte, key *[32]byte) {
	switch {
	case useAVX:
		hChaCha20AVX(out, nonce, key)
	case useSSSE3:
		hChaCha20SSSE3(out, nonce, key)
	case useSSE2:
		hChaCha20SSE2(out, nonce, key)
	default:
		hChaCha20Generic(out, nonce, key)
	}
}

func xorKeyStream(dst, src []byte, block, state *[64]byte, rounds int) int {
	switch {
	case useAVX2:
		return xorKeyStreamAVX2(dst, src, block, state, rounds)
	case useAVX:
		return xorKeyStreamAVX(dst, src, block, state, rounds)
	case useSSSE3:
		return xorKeyStreamSSSE3(dst, src, block, state, rounds)
	case useSSE2:
		return xorKeyStreamSSE2(dst, src, block, state, rounds)
	default:
		return xorKeyStreamGeneric(dst, src, block, state, rounds)
	}
}
