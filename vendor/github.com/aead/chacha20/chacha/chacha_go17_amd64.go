// Copyright (c) 2017 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// +build go1.7,amd64,!gccgo,!appengine,!nacl

package chacha

func init() {
	useSSE2 = true
	useSSSE3 = supportsSSSE3()
	useAVX2 = supportsAVX2()
}

// This function is implemented in chacha_amd64.s
//go:noescape
func initialize(state *[64]byte, key []byte, nonce *[16]byte)

// This function is implemented in chacha_amd64.s
//go:noescape
func supportsSSSE3() bool

// This function is implemented in chachaAVX2_amd64.s
//go:noescape
func supportsAVX2() bool

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

// This function is implemented in chachaAVX2_amd64.s
//go:noescape
func xorKeyStreamAVX2(dst, src []byte, block, state *[64]byte, rounds int) int

func hChaCha20(out *[32]byte, nonce *[16]byte, key *[32]byte) {
	if useAVX2 {
		hChaCha20AVX(out, nonce, key)
	} else if useSSSE3 {
		hChaCha20SSSE3(out, nonce, key)
	} else if useSSE2 { // on amd64 this is  always true - neccessary for testing generic on amd64
		hChaCha20SSE2(out, nonce, key)
	} else {
		hChaCha20Generic(out, nonce, key)
	}
}

func xorKeyStream(dst, src []byte, block, state *[64]byte, rounds int) int {
	if useAVX2 {
		return xorKeyStreamAVX2(dst, src, block, state, rounds)
	} else if useSSSE3 {
		return xorKeyStreamSSSE3(dst, src, block, state, rounds)
	} else if useSSE2 { // on amd64 this is  always true - neccessary for testing generic on amd64
		return xorKeyStreamSSE2(dst, src, block, state, rounds)
	}
	return xorKeyStreamGeneric(dst, src, block, state, rounds)
}
