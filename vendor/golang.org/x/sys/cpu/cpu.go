// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package cpu implements processor feature detection for
// various CPU architectures.
package cpu

// CacheLinePad is used to pad structs to avoid false sharing.
type CacheLinePad struct{ _ [cacheLineSize]byte }

// X86 contains the supported CPU features of the
// current X86/AMD64 platform. If the current platform
// is not X86/AMD64 then all feature flags are false.
//
// X86 is padded to avoid false sharing. Further the HasAVX
// and HasAVX2 are only set if the OS supports XMM and YMM
// registers in addition to the CPUID feature bit being set.
var X86 struct {
	_            CacheLinePad
	HasAES       bool // AES hardware implementation (AES NI)
	HasADX       bool // Multi-precision add-carry instruction extensions
	HasAVX       bool // Advanced vector extension
	HasAVX2      bool // Advanced vector extension 2
	HasBMI1      bool // Bit manipulation instruction set 1
	HasBMI2      bool // Bit manipulation instruction set 2
	HasERMS      bool // Enhanced REP for MOVSB and STOSB
	HasFMA       bool // Fused-multiply-add instructions
	HasOSXSAVE   bool // OS supports XSAVE/XRESTOR for saving/restoring XMM registers.
	HasPCLMULQDQ bool // PCLMULQDQ instruction - most often used for AES-GCM
	HasPOPCNT    bool // Hamming weight instruction POPCNT.
	HasSSE2      bool // Streaming SIMD extension 2 (always available on amd64)
	HasSSE3      bool // Streaming SIMD extension 3
	HasSSSE3     bool // Supplemental streaming SIMD extension 3
	HasSSE41     bool // Streaming SIMD extension 4 and 4.1
	HasSSE42     bool // Streaming SIMD extension 4 and 4.2
	_            CacheLinePad
}
