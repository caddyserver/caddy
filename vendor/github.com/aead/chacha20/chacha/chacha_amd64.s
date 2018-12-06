// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// +build amd64,!gccgo,!appengine,!nacl

#include "const.s"
#include "macro.s"

// FINALIZE xors len bytes from src and block using
// the temp. registers t0 and t1 and writes the result
// to dst.
#define FINALIZE(dst, src, block, len, t0, t1) \
	XORQ t0, t0;       \
	XORQ t1, t1;       \
	FINALIZE_LOOP:;    \
	MOVB 0(src), t0;   \
	MOVB 0(block), t1; \
	XORQ t0, t1;       \
	MOVB t1, 0(dst);   \
	INCQ src;          \
	INCQ block;        \
	INCQ dst;          \
	DECQ len;          \
	JG   FINALIZE_LOOP \

#define Dst DI
#define Nonce AX
#define Key BX
#define Rounds DX

// func initialize(state *[64]byte, key []byte, nonce *[16]byte)
TEXT ·initialize(SB), 4, $0-40
	MOVQ state+0(FP), Dst
	MOVQ key+8(FP), Key
	MOVQ nonce+32(FP), Nonce

	MOVOU ·sigma<>(SB), X0
	MOVOU 0*16(Key), X1
	MOVOU 1*16(Key), X2
	MOVOU 0*16(Nonce), X3

	MOVOU X0, 0*16(Dst)
	MOVOU X1, 1*16(Dst)
	MOVOU X2, 2*16(Dst)
	MOVOU X3, 3*16(Dst)
	RET

// func hChaCha20AVX(out *[32]byte, nonce *[16]byte, key *[32]byte)
TEXT ·hChaCha20AVX(SB), 4, $0-24
	MOVQ out+0(FP), Dst
	MOVQ nonce+8(FP), Nonce
	MOVQ key+16(FP), Key

	VMOVDQU ·sigma<>(SB), X0
	VMOVDQU 0*16(Key), X1
	VMOVDQU 1*16(Key), X2
	VMOVDQU 0*16(Nonce), X3
	VMOVDQU ·rol16_AVX2<>(SB), X5
	VMOVDQU ·rol8_AVX2<>(SB), X6
	MOVQ    $20, Rounds

CHACHA_LOOP:
	CHACHA_QROUND_AVX(X0, X1, X2, X3, X4, X5, X6)
	CHACHA_SHUFFLE_AVX(X1, X2, X3)
	CHACHA_QROUND_AVX(X0, X1, X2, X3, X4, X5, X6)
	CHACHA_SHUFFLE_AVX(X3, X2, X1)
	SUBQ $2, Rounds
	JNZ  CHACHA_LOOP

	VMOVDQU X0, 0*16(Dst)
	VMOVDQU X3, 1*16(Dst)
	VZEROUPPER
	RET

// func hChaCha20SSE2(out *[32]byte, nonce *[16]byte, key *[32]byte)
TEXT ·hChaCha20SSE2(SB), 4, $0-24
	MOVQ out+0(FP), Dst
	MOVQ nonce+8(FP), Nonce
	MOVQ key+16(FP), Key

	MOVOU ·sigma<>(SB), X0
	MOVOU 0*16(Key), X1
	MOVOU 1*16(Key), X2
	MOVOU 0*16(Nonce), X3
	MOVQ  $20, Rounds

CHACHA_LOOP:
	CHACHA_QROUND_SSE2(X0, X1, X2, X3, X4)
	CHACHA_SHUFFLE_SSE(X1, X2, X3)
	CHACHA_QROUND_SSE2(X0, X1, X2, X3, X4)
	CHACHA_SHUFFLE_SSE(X3, X2, X1)
	SUBQ $2, Rounds
	JNZ  CHACHA_LOOP

	MOVOU X0, 0*16(Dst)
	MOVOU X3, 1*16(Dst)
	RET

// func hChaCha20SSSE3(out *[32]byte, nonce *[16]byte, key *[32]byte)
TEXT ·hChaCha20SSSE3(SB), 4, $0-24
	MOVQ out+0(FP), Dst
	MOVQ nonce+8(FP), Nonce
	MOVQ key+16(FP), Key

	MOVOU ·sigma<>(SB), X0
	MOVOU 0*16(Key), X1
	MOVOU 1*16(Key), X2
	MOVOU 0*16(Nonce), X3
	MOVOU ·rol16<>(SB), X5
	MOVOU ·rol8<>(SB), X6
	MOVQ  $20, Rounds

chacha_loop:
	CHACHA_QROUND_SSSE3(X0, X1, X2, X3, X4, X5, X6)
	CHACHA_SHUFFLE_SSE(X1, X2, X3)
	CHACHA_QROUND_SSSE3(X0, X1, X2, X3, X4, X5, X6)
	CHACHA_SHUFFLE_SSE(X3, X2, X1)
	SUBQ $2, Rounds
	JNZ  chacha_loop

	MOVOU X0, 0*16(Dst)
	MOVOU X3, 1*16(Dst)
	RET

#undef Dst
#undef Nonce
#undef Key
#undef Rounds

#define Dst DI
#define Src SI
#define Len R12
#define Rounds DX
#define Buffer BX
#define State AX
#define Stack SP
#define SavedSP R8
#define Tmp0 R9
#define Tmp1 R10
#define Tmp2 R11

// func xorKeyStreamSSE2(dst, src []byte, block, state *[64]byte, rounds int) int
TEXT ·xorKeyStreamSSE2(SB), 4, $112-80
	MOVQ dst_base+0(FP), Dst
	MOVQ src_base+24(FP), Src
	MOVQ block+48(FP), Buffer
	MOVQ state+56(FP), State
	MOVQ rounds+64(FP), Rounds
	MOVQ src_len+32(FP), Len

	MOVOU 0*16(State), X0
	MOVOU 1*16(State), X1
	MOVOU 2*16(State), X2
	MOVOU 3*16(State), X3

	MOVQ Stack, SavedSP
	ADDQ $16, Stack
	ANDQ $-16, Stack

	TESTQ Len, Len
	JZ    DONE

	MOVOU ·one<>(SB), X4
	MOVO  X0, 0*16(Stack)
	MOVO  X1, 1*16(Stack)
	MOVO  X2, 2*16(Stack)
	MOVO  X3, 3*16(Stack)
	MOVO  X4, 4*16(Stack)

	CMPQ Len, $64
	JLE  GENERATE_KEYSTREAM_64
	CMPQ Len, $128
	JLE  GENERATE_KEYSTREAM_128
	CMPQ Len, $192
	JLE  GENERATE_KEYSTREAM_192

GENERATE_KEYSTREAM_256:
	MOVO  X0, X12
	MOVO  X1, X13
	MOVO  X2, X14
	MOVO  X3, X15
	PADDQ 4*16(Stack), X15
	MOVO  X0, X8
	MOVO  X1, X9
	MOVO  X2, X10
	MOVO  X15, X11
	PADDQ 4*16(Stack), X11
	MOVO  X0, X4
	MOVO  X1, X5
	MOVO  X2, X6
	MOVO  X11, X7
	PADDQ 4*16(Stack), X7
	MOVQ  Rounds, Tmp0

	MOVO X3, 3*16(Stack) // Save X3

CHACHA_LOOP_256:
	MOVO X4, 5*16(Stack)
	CHACHA_QROUND_SSE2(X0, X1, X2, X3, X4)
	CHACHA_QROUND_SSE2(X12, X13, X14, X15, X4)
	MOVO 5*16(Stack), X4
	MOVO X0, 5*16(Stack)
	CHACHA_QROUND_SSE2(X8, X9, X10, X11, X0)
	CHACHA_QROUND_SSE2(X4, X5, X6, X7, X0)
	MOVO 5*16(Stack), X0
	CHACHA_SHUFFLE_SSE(X1, X2, X3)
	CHACHA_SHUFFLE_SSE(X13, X14, X15)
	CHACHA_SHUFFLE_SSE(X9, X10, X11)
	CHACHA_SHUFFLE_SSE(X5, X6, X7)
	MOVO X4, 5*16(Stack)
	CHACHA_QROUND_SSE2(X0, X1, X2, X3, X4)
	CHACHA_QROUND_SSE2(X12, X13, X14, X15, X4)
	MOVO 5*16(Stack), X4
	MOVO X0, 5*16(Stack)
	CHACHA_QROUND_SSE2(X8, X9, X10, X11, X0)
	CHACHA_QROUND_SSE2(X4, X5, X6, X7, X0)
	MOVO 5*16(Stack), X0
	CHACHA_SHUFFLE_SSE(X3, X2, X1)
	CHACHA_SHUFFLE_SSE(X15, X14, X13)
	CHACHA_SHUFFLE_SSE(X11, X10, X9)
	CHACHA_SHUFFLE_SSE(X7, X6, X5)
	SUBQ $2, Tmp0
	JNZ  CHACHA_LOOP_256

	PADDL 0*16(Stack), X0
	PADDL 1*16(Stack), X1
	PADDL 2*16(Stack), X2
	PADDL 3*16(Stack), X3
	MOVO  X4, 5*16(Stack) // Save X4
	XOR_SSE(Dst, Src, 0, X0, X1, X2, X3, X4)
	MOVO  5*16(Stack), X4 // Restore X4

	MOVO  0*16(Stack), X0
	MOVO  1*16(Stack), X1
	MOVO  2*16(Stack), X2
	MOVO  3*16(Stack), X3
	PADDQ 4*16(Stack), X3

	PADDL X0, X12
	PADDL X1, X13
	PADDL X2, X14
	PADDL X3, X15
	PADDQ 4*16(Stack), X3
	PADDL X0, X8
	PADDL X1, X9
	PADDL X2, X10
	PADDL X3, X11
	PADDQ 4*16(Stack), X3
	PADDL X0, X4
	PADDL X1, X5
	PADDL X2, X6
	PADDL X3, X7
	PADDQ 4*16(Stack), X3

	XOR_SSE(Dst, Src, 64, X12, X13, X14, X15, X0)
	XOR_SSE(Dst, Src, 128, X8, X9, X10, X11, X0)
	MOVO 0*16(Stack), X0 // Restore X0
	ADDQ $192, Dst
	ADDQ $192, Src
	SUBQ $192, Len

	CMPQ Len, $64
	JL   BUFFER_KEYSTREAM

	XOR_SSE(Dst, Src, 0, X4, X5, X6, X7, X8)
	ADDQ $64, Dst
	ADDQ $64, Src
	SUBQ $64, Len
	JZ   DONE
	CMPQ Len, $64               // If Len <= 64 -> gen. only 64 byte keystream.
	JLE  GENERATE_KEYSTREAM_64
	CMPQ Len, $128              // If 64 < Len <= 128 -> gen. only 128 byte keystream.
	JLE  GENERATE_KEYSTREAM_128
	CMPQ Len, $192              // If Len > 192 -> repeat, otherwise Len > 128 && Len <= 192 -> gen. 192 byte keystream
	JG   GENERATE_KEYSTREAM_256

GENERATE_KEYSTREAM_192:
	MOVO  X0, X12
	MOVO  X1, X13
	MOVO  X2, X14
	MOVO  X3, X15
	MOVO  X0, X8
	MOVO  X1, X9
	MOVO  X2, X10
	MOVO  X3, X11
	PADDQ 4*16(Stack), X11
	MOVO  X0, X4
	MOVO  X1, X5
	MOVO  X2, X6
	MOVO  X11, X7
	PADDQ 4*16(Stack), X7
	MOVQ  Rounds, Tmp0

CHACHA_LOOP_192:
	CHACHA_QROUND_SSE2(X12, X13, X14, X15, X0)
	CHACHA_QROUND_SSE2(X8, X9, X10, X11, X0)
	CHACHA_QROUND_SSE2(X4, X5, X6, X7, X0)
	CHACHA_SHUFFLE_SSE(X13, X14, X15)
	CHACHA_SHUFFLE_SSE(X9, X10, X11)
	CHACHA_SHUFFLE_SSE(X5, X6, X7)
	CHACHA_QROUND_SSE2(X12, X13, X14, X15, X0)
	CHACHA_QROUND_SSE2(X8, X9, X10, X11, X0)
	CHACHA_QROUND_SSE2(X4, X5, X6, X7, X0)
	CHACHA_SHUFFLE_SSE(X15, X14, X13)
	CHACHA_SHUFFLE_SSE(X11, X10, X9)
	CHACHA_SHUFFLE_SSE(X7, X6, X5)
	SUBQ $2, Tmp0
	JNZ  CHACHA_LOOP_192

	MOVO  0*16(Stack), X0 // Restore X0
	PADDL X0, X12
	PADDL X1, X13
	PADDL X2, X14
	PADDL X3, X15
	PADDQ 4*16(Stack), X3
	PADDL X0, X8
	PADDL X1, X9
	PADDL X2, X10
	PADDL X3, X11
	PADDQ 4*16(Stack), X3
	PADDL X0, X4
	PADDL X1, X5
	PADDL X2, X6
	PADDL X3, X7
	PADDQ 4*16(Stack), X3

	XOR_SSE(Dst, Src, 0, X12, X13, X14, X15, X0)
	XOR_SSE(Dst, Src, 64, X8, X9, X10, X11, X0)
	MOVO 0*16(Stack), X0 // Restore X0
	ADDQ $128, Dst
	ADDQ $128, Src
	SUBQ $128, Len

	CMPQ Len, $64
	JL   BUFFER_KEYSTREAM

	XOR_SSE(Dst, Src, 0, X4, X5, X6, X7, X8)
	ADDQ $64, Dst
	ADDQ $64, Src
	SUBQ $64, Len
	JZ   DONE
	CMPQ Len, $64              // If Len <= 64 -> gen. only 64 byte keystream.
	JLE  GENERATE_KEYSTREAM_64

GENERATE_KEYSTREAM_128:
	MOVO  X0, X8
	MOVO  X1, X9
	MOVO  X2, X10
	MOVO  X3, X11
	MOVO  X0, X4
	MOVO  X1, X5
	MOVO  X2, X6
	MOVO  X3, X7
	PADDQ 4*16(Stack), X7
	MOVQ  Rounds, Tmp0

CHACHA_LOOP_128:
	CHACHA_QROUND_SSE2(X8, X9, X10, X11, X12)
	CHACHA_QROUND_SSE2(X4, X5, X6, X7, X12)
	CHACHA_SHUFFLE_SSE(X9, X10, X11)
	CHACHA_SHUFFLE_SSE(X5, X6, X7)
	CHACHA_QROUND_SSE2(X8, X9, X10, X11, X12)
	CHACHA_QROUND_SSE2(X4, X5, X6, X7, X12)
	CHACHA_SHUFFLE_SSE(X11, X10, X9)
	CHACHA_SHUFFLE_SSE(X7, X6, X5)
	SUBQ $2, Tmp0
	JNZ  CHACHA_LOOP_128

	PADDL X0, X8
	PADDL X1, X9
	PADDL X2, X10
	PADDL X3, X11
	PADDQ 4*16(Stack), X3
	PADDL X0, X4
	PADDL X1, X5
	PADDL X2, X6
	PADDL X3, X7
	PADDQ 4*16(Stack), X3

	XOR_SSE(Dst, Src, 0, X8, X9, X10, X11, X12)
	ADDQ $64, Dst
	ADDQ $64, Src
	SUBQ $64, Len

	CMPQ Len, $64
	JL   BUFFER_KEYSTREAM

	XOR_SSE(Dst, Src, 0, X4, X5, X6, X7, X8)
	ADDQ $64, Dst
	ADDQ $64, Src
	SUBQ $64, Len
	JZ   DONE     // If Len == 0 -> DONE, otherwise Len <= 64 -> gen 64 byte keystream

GENERATE_KEYSTREAM_64:
	MOVO X0, X4
	MOVO X1, X5
	MOVO X2, X6
	MOVO X3, X7
	MOVQ Rounds, Tmp0

CHACHA_LOOP_64:
	CHACHA_QROUND_SSE2(X4, X5, X6, X7, X8)
	CHACHA_SHUFFLE_SSE(X5, X6, X7)
	CHACHA_QROUND_SSE2(X4, X5, X6, X7, X8)
	CHACHA_SHUFFLE_SSE(X7, X6, X5)
	SUBQ $2, Tmp0
	JNZ  CHACHA_LOOP_64

	PADDL X0, X4
	PADDL X1, X5
	PADDL X2, X6
	PADDL X3, X7
	PADDQ 4*16(Stack), X3

	CMPQ Len, $64
	JL   BUFFER_KEYSTREAM

	XOR_SSE(Dst, Src, 0, X4, X5, X6, X7, X8)
	ADDQ $64, Src
	ADDQ $64, Dst
	SUBQ $64, Len
	JMP  DONE     // jump directly to DONE - there is no keystream to buffer, Len == 0 always true.

BUFFER_KEYSTREAM:
	MOVOU X4, 0*16(Buffer)
	MOVOU X5, 1*16(Buffer)
	MOVOU X6, 2*16(Buffer)
	MOVOU X7, 3*16(Buffer)
	MOVQ  Len, Tmp0
	FINALIZE(Dst, Src, Buffer, Tmp0, Tmp1, Tmp2)

DONE:
	MOVQ  SavedSP, Stack  // Restore stack pointer
	MOVOU X3, 3*16(State)
	MOVQ  Len, ret+72(FP)
	RET

// func xorKeyStreamSSSE3(dst, src []byte, block, state *[64]byte, rounds int) int
TEXT ·xorKeyStreamSSSE3(SB), 4, $144-80
	MOVQ dst_base+0(FP), Dst
	MOVQ src_base+24(FP), Src
	MOVQ block+48(FP), Buffer
	MOVQ state+56(FP), State
	MOVQ rounds+64(FP), Rounds
	MOVQ src_len+32(FP), Len

	MOVOU 0*16(State), X0
	MOVOU 1*16(State), X1
	MOVOU 2*16(State), X2
	MOVOU 3*16(State), X3

	MOVQ Stack, SavedSP
	ADDQ $16, Stack
	ANDQ $-16, Stack

	TESTQ Len, Len
	JZ    DONE

	MOVOU ·one<>(SB), X4
	MOVOU ·rol16<>(SB), X5
	MOVOU ·rol8<>(SB), X6
	MOVO  X0, 0*16(Stack)
	MOVO  X1, 1*16(Stack)
	MOVO  X2, 2*16(Stack)
	MOVO  X3, 3*16(Stack)
	MOVO  X4, 4*16(Stack)
	MOVO  X5, 6*16(Stack)
	MOVO  X6, 7*16(Stack)

	CMPQ Len, $64
	JLE  GENERATE_KEYSTREAM_64
	CMPQ Len, $128
	JLE  GENERATE_KEYSTREAM_128
	CMPQ Len, $192
	JLE  GENERATE_KEYSTREAM_192

GENERATE_KEYSTREAM_256:
	MOVO  X0, X12
	MOVO  X1, X13
	MOVO  X2, X14
	MOVO  X3, X15
	PADDQ 4*16(Stack), X15
	MOVO  X0, X8
	MOVO  X1, X9
	MOVO  X2, X10
	MOVO  X15, X11
	PADDQ 4*16(Stack), X11
	MOVO  X0, X4
	MOVO  X1, X5
	MOVO  X2, X6
	MOVO  X11, X7
	PADDQ 4*16(Stack), X7
	MOVQ  Rounds, Tmp0

	MOVO X3, 3*16(Stack) // Save X3

CHACHA_LOOP_256:
	MOVO X4, 5*16(Stack)
	CHACHA_QROUND_SSSE3(X0, X1, X2, X3, X4, 6*16(Stack), 7*16(Stack))
	CHACHA_QROUND_SSSE3(X12, X13, X14, X15, X4, 6*16(Stack), 7*16(Stack))
	MOVO 5*16(Stack), X4
	MOVO X0, 5*16(Stack)
	CHACHA_QROUND_SSSE3(X8, X9, X10, X11, X0, 6*16(Stack), 7*16(Stack))
	CHACHA_QROUND_SSSE3(X4, X5, X6, X7, X0, 6*16(Stack), 7*16(Stack))
	MOVO 5*16(Stack), X0
	CHACHA_SHUFFLE_SSE(X1, X2, X3)
	CHACHA_SHUFFLE_SSE(X13, X14, X15)
	CHACHA_SHUFFLE_SSE(X9, X10, X11)
	CHACHA_SHUFFLE_SSE(X5, X6, X7)
	MOVO X4, 5*16(Stack)
	CHACHA_QROUND_SSSE3(X0, X1, X2, X3, X4, 6*16(Stack), 7*16(Stack))
	CHACHA_QROUND_SSSE3(X12, X13, X14, X15, X4, 6*16(Stack), 7*16(Stack))
	MOVO 5*16(Stack), X4
	MOVO X0, 5*16(Stack)
	CHACHA_QROUND_SSSE3(X8, X9, X10, X11, X0, 6*16(Stack), 7*16(Stack))
	CHACHA_QROUND_SSSE3(X4, X5, X6, X7, X0, 6*16(Stack), 7*16(Stack))
	MOVO 5*16(Stack), X0
	CHACHA_SHUFFLE_SSE(X3, X2, X1)
	CHACHA_SHUFFLE_SSE(X15, X14, X13)
	CHACHA_SHUFFLE_SSE(X11, X10, X9)
	CHACHA_SHUFFLE_SSE(X7, X6, X5)
	SUBQ $2, Tmp0
	JNZ  CHACHA_LOOP_256

	PADDL 0*16(Stack), X0
	PADDL 1*16(Stack), X1
	PADDL 2*16(Stack), X2
	PADDL 3*16(Stack), X3
	MOVO  X4, 5*16(Stack) // Save X4
	XOR_SSE(Dst, Src, 0, X0, X1, X2, X3, X4)
	MOVO  5*16(Stack), X4 // Restore X4

	MOVO  0*16(Stack), X0
	MOVO  1*16(Stack), X1
	MOVO  2*16(Stack), X2
	MOVO  3*16(Stack), X3
	PADDQ 4*16(Stack), X3

	PADDL X0, X12
	PADDL X1, X13
	PADDL X2, X14
	PADDL X3, X15
	PADDQ 4*16(Stack), X3
	PADDL X0, X8
	PADDL X1, X9
	PADDL X2, X10
	PADDL X3, X11
	PADDQ 4*16(Stack), X3
	PADDL X0, X4
	PADDL X1, X5
	PADDL X2, X6
	PADDL X3, X7
	PADDQ 4*16(Stack), X3

	XOR_SSE(Dst, Src, 64, X12, X13, X14, X15, X0)
	XOR_SSE(Dst, Src, 128, X8, X9, X10, X11, X0)
	MOVO 0*16(Stack), X0 // Restore X0
	ADDQ $192, Dst
	ADDQ $192, Src
	SUBQ $192, Len

	CMPQ Len, $64
	JL   BUFFER_KEYSTREAM

	XOR_SSE(Dst, Src, 0, X4, X5, X6, X7, X8)
	ADDQ $64, Dst
	ADDQ $64, Src
	SUBQ $64, Len
	JZ   DONE
	CMPQ Len, $64               // If Len <= 64 -> gen. only 64 byte keystream.
	JLE  GENERATE_KEYSTREAM_64
	CMPQ Len, $128              // If 64 < Len <= 128 -> gen. only 128 byte keystream.
	JLE  GENERATE_KEYSTREAM_128
	CMPQ Len, $192              // If Len > 192 -> repeat, otherwise Len > 128 && Len <= 192 -> gen. 192 byte keystream
	JG   GENERATE_KEYSTREAM_256

GENERATE_KEYSTREAM_192:
	MOVO  X0, X12
	MOVO  X1, X13
	MOVO  X2, X14
	MOVO  X3, X15
	MOVO  X0, X8
	MOVO  X1, X9
	MOVO  X2, X10
	MOVO  X3, X11
	PADDQ 4*16(Stack), X11
	MOVO  X0, X4
	MOVO  X1, X5
	MOVO  X2, X6
	MOVO  X11, X7
	PADDQ 4*16(Stack), X7
	MOVQ  Rounds, Tmp0

	MOVO 6*16(Stack), X1 // Load 16 bit rotate-left constant
	MOVO 7*16(Stack), X2 // Load 8 bit rotate-left constant

CHACHA_LOOP_192:
	CHACHA_QROUND_SSSE3(X12, X13, X14, X15, X0, X1, X2)
	CHACHA_QROUND_SSSE3(X8, X9, X10, X11, X0, X1, X2)
	CHACHA_QROUND_SSSE3(X4, X5, X6, X7, X0, X1, X2)
	CHACHA_SHUFFLE_SSE(X13, X14, X15)
	CHACHA_SHUFFLE_SSE(X9, X10, X11)
	CHACHA_SHUFFLE_SSE(X5, X6, X7)
	CHACHA_QROUND_SSSE3(X12, X13, X14, X15, X0, X1, X2)
	CHACHA_QROUND_SSSE3(X8, X9, X10, X11, X0, X1, X2)
	CHACHA_QROUND_SSSE3(X4, X5, X6, X7, X0, X1, X2)
	CHACHA_SHUFFLE_SSE(X15, X14, X13)
	CHACHA_SHUFFLE_SSE(X11, X10, X9)
	CHACHA_SHUFFLE_SSE(X7, X6, X5)
	SUBQ $2, Tmp0
	JNZ  CHACHA_LOOP_192

	MOVO  0*16(Stack), X0 // Restore X0
	MOVO  1*16(Stack), X1 // Restore X1
	MOVO  2*16(Stack), X2 // Restore X2
	PADDL X0, X12
	PADDL X1, X13
	PADDL X2, X14
	PADDL X3, X15
	PADDQ 4*16(Stack), X3
	PADDL X0, X8
	PADDL X1, X9
	PADDL X2, X10
	PADDL X3, X11
	PADDQ 4*16(Stack), X3
	PADDL X0, X4
	PADDL X1, X5
	PADDL X2, X6
	PADDL X3, X7
	PADDQ 4*16(Stack), X3

	XOR_SSE(Dst, Src, 0, X12, X13, X14, X15, X0)
	XOR_SSE(Dst, Src, 64, X8, X9, X10, X11, X0)
	MOVO 0*16(Stack), X0 // Restore X0
	ADDQ $128, Dst
	ADDQ $128, Src
	SUBQ $128, Len

	CMPQ Len, $64
	JL   BUFFER_KEYSTREAM

	XOR_SSE(Dst, Src, 0, X4, X5, X6, X7, X8)
	ADDQ $64, Dst
	ADDQ $64, Src
	SUBQ $64, Len
	JZ   DONE
	CMPQ Len, $64              // If Len <= 64 -> gen. only 64 byte keystream.
	JLE  GENERATE_KEYSTREAM_64

GENERATE_KEYSTREAM_128:
	MOVO  X0, X8
	MOVO  X1, X9
	MOVO  X2, X10
	MOVO  X3, X11
	MOVO  X0, X4
	MOVO  X1, X5
	MOVO  X2, X6
	MOVO  X3, X7
	PADDQ 4*16(Stack), X7
	MOVQ  Rounds, Tmp0

	MOVO 6*16(Stack), X13 // Load 16 bit rotate-left constant
	MOVO 7*16(Stack), X14 // Load 8 bit rotate-left constant

CHACHA_LOOP_128:
	CHACHA_QROUND_SSSE3(X8, X9, X10, X11, X12, X13, X14)
	CHACHA_QROUND_SSSE3(X4, X5, X6, X7, X12, X13, X14)
	CHACHA_SHUFFLE_SSE(X9, X10, X11)
	CHACHA_SHUFFLE_SSE(X5, X6, X7)
	CHACHA_QROUND_SSSE3(X8, X9, X10, X11, X12, X13, X14)
	CHACHA_QROUND_SSSE3(X4, X5, X6, X7, X12, X13, X14)
	CHACHA_SHUFFLE_SSE(X11, X10, X9)
	CHACHA_SHUFFLE_SSE(X7, X6, X5)
	SUBQ $2, Tmp0
	JNZ  CHACHA_LOOP_128

	PADDL X0, X8
	PADDL X1, X9
	PADDL X2, X10
	PADDL X3, X11
	PADDQ 4*16(Stack), X3
	PADDL X0, X4
	PADDL X1, X5
	PADDL X2, X6
	PADDL X3, X7
	PADDQ 4*16(Stack), X3

	XOR_SSE(Dst, Src, 0, X8, X9, X10, X11, X12)
	ADDQ $64, Dst
	ADDQ $64, Src
	SUBQ $64, Len

	CMPQ Len, $64
	JL   BUFFER_KEYSTREAM

	XOR_SSE(Dst, Src, 0, X4, X5, X6, X7, X8)
	ADDQ $64, Dst
	ADDQ $64, Src
	SUBQ $64, Len
	JZ   DONE     // If Len == 0 -> DONE, otherwise Len <= 64 -> gen 64 byte keystream

GENERATE_KEYSTREAM_64:
	MOVO X0, X4
	MOVO X1, X5
	MOVO X2, X6
	MOVO X3, X7
	MOVQ Rounds, Tmp0

	MOVO 6*16(Stack), X9  // Load 16 bit rotate-left constant
	MOVO 7*16(Stack), X10 // Load 8 bit rotate-left constant

CHACHA_LOOP_64:
	CHACHA_QROUND_SSSE3(X4, X5, X6, X7, X8, X9, X10)
	CHACHA_SHUFFLE_SSE(X5, X6, X7)
	CHACHA_QROUND_SSSE3(X4, X5, X6, X7, X8, X9, X10)
	CHACHA_SHUFFLE_SSE(X7, X6, X5)
	SUBQ $2, Tmp0
	JNZ  CHACHA_LOOP_64

	PADDL X0, X4
	PADDL X1, X5
	PADDL X2, X6
	PADDL X3, X7
	PADDQ 4*16(Stack), X3

	CMPQ Len, $64
	JL   BUFFER_KEYSTREAM

	XOR_SSE(Dst, Src, 0, X4, X5, X6, X7, X8)
	ADDQ $64, Src
	ADDQ $64, Dst
	SUBQ $64, Len
	JMP  DONE     // jump directly to DONE - there is no keystream to buffer, Len == 0 always true.

BUFFER_KEYSTREAM:
	MOVOU X4, 0*16(Buffer)
	MOVOU X5, 1*16(Buffer)
	MOVOU X6, 2*16(Buffer)
	MOVOU X7, 3*16(Buffer)
	MOVQ  Len, Tmp0
	FINALIZE(Dst, Src, Buffer, Tmp0, Tmp1, Tmp2)

DONE:
	MOVQ  SavedSP, Stack  // Restore stack pointer
	MOVOU X3, 3*16(State)
	MOVQ  Len, ret+72(FP)
	RET

// func xorKeyStreamAVX(dst, src []byte, block, state *[64]byte, rounds int) int
TEXT ·xorKeyStreamAVX(SB), 4, $144-80
	MOVQ dst_base+0(FP), Dst
	MOVQ src_base+24(FP), Src
	MOVQ block+48(FP), Buffer
	MOVQ state+56(FP), State
	MOVQ rounds+64(FP), Rounds
	MOVQ src_len+32(FP), Len

	VMOVDQU 0*16(State), X0
	VMOVDQU 1*16(State), X1
	VMOVDQU 2*16(State), X2
	VMOVDQU 3*16(State), X3

	MOVQ Stack, SavedSP
	ADDQ $16, Stack
	ANDQ $-16, Stack

	TESTQ Len, Len
	JZ    DONE

	VMOVDQU ·one<>(SB), X4
	VMOVDQU ·rol16<>(SB), X5
	VMOVDQU ·rol8<>(SB), X6
	VMOVDQA X0, 0*16(Stack)
	VMOVDQA X1, 1*16(Stack)
	VMOVDQA X2, 2*16(Stack)
	VMOVDQA X3, 3*16(Stack)
	VMOVDQA X4, 4*16(Stack)
	VMOVDQA X5, 6*16(Stack)
	VMOVDQA X6, 7*16(Stack)

	CMPQ Len, $64
	JLE  GENERATE_KEYSTREAM_64
	CMPQ Len, $128
	JLE  GENERATE_KEYSTREAM_128
	CMPQ Len, $192
	JLE  GENERATE_KEYSTREAM_192

GENERATE_KEYSTREAM_256:
	VMOVDQA X0, X12
	VMOVDQA X1, X13
	VMOVDQA X2, X14
	VMOVDQA X3, X15
	VPADDQ  4*16(Stack), X15, X15
	VMOVDQA X0, X8
	VMOVDQA X1, X9
	VMOVDQA X2, X10
	VMOVDQA X15, X11
	VPADDQ  4*16(Stack), X11, X11
	VMOVDQA X0, X4
	VMOVDQA X1, X5
	VMOVDQA X2, X6
	VMOVDQA X11, X7
	VPADDQ  4*16(Stack), X7, X7
	MOVQ    Rounds, Tmp0

	VMOVDQA X3, 3*16(Stack) // Save X3

CHACHA_LOOP_256:
	VMOVDQA X4, 5*16(Stack)
	CHACHA_QROUND_AVX(X0, X1, X2, X3, X4, 6*16(Stack), 7*16(Stack))
	CHACHA_QROUND_AVX(X12, X13, X14, X15, X4, 6*16(Stack), 7*16(Stack))
	VMOVDQA 5*16(Stack), X4
	VMOVDQA X0, 5*16(Stack)
	CHACHA_QROUND_AVX(X8, X9, X10, X11, X0, 6*16(Stack), 7*16(Stack))
	CHACHA_QROUND_AVX(X4, X5, X6, X7, X0, 6*16(Stack), 7*16(Stack))
	VMOVDQA 5*16(Stack), X0
	CHACHA_SHUFFLE_AVX(X1, X2, X3)
	CHACHA_SHUFFLE_AVX(X13, X14, X15)
	CHACHA_SHUFFLE_AVX(X9, X10, X11)
	CHACHA_SHUFFLE_AVX(X5, X6, X7)
	VMOVDQA X4, 5*16(Stack)
	CHACHA_QROUND_AVX(X0, X1, X2, X3, X4, 6*16(Stack), 7*16(Stack))
	CHACHA_QROUND_AVX(X12, X13, X14, X15, X4, 6*16(Stack), 7*16(Stack))
	VMOVDQA 5*16(Stack), X4
	VMOVDQA X0, 5*16(Stack)
	CHACHA_QROUND_AVX(X8, X9, X10, X11, X0, 6*16(Stack), 7*16(Stack))
	CHACHA_QROUND_AVX(X4, X5, X6, X7, X0, 6*16(Stack), 7*16(Stack))
	VMOVDQA 5*16(Stack), X0
	CHACHA_SHUFFLE_AVX(X3, X2, X1)
	CHACHA_SHUFFLE_AVX(X15, X14, X13)
	CHACHA_SHUFFLE_AVX(X11, X10, X9)
	CHACHA_SHUFFLE_AVX(X7, X6, X5)
	SUBQ    $2, Tmp0
	JNZ     CHACHA_LOOP_256

	VPADDD  0*16(Stack), X0, X0
	VPADDD  1*16(Stack), X1, X1
	VPADDD  2*16(Stack), X2, X2
	VPADDD  3*16(Stack), X3, X3
	VMOVDQA X4, 5*16(Stack)     // Save X4
	XOR_AVX(Dst, Src, 0, X0, X1, X2, X3, X4)
	VMOVDQA 5*16(Stack), X4     // Restore X4

	VMOVDQA 0*16(Stack), X0
	VMOVDQA 1*16(Stack), X1
	VMOVDQA 2*16(Stack), X2
	VMOVDQA 3*16(Stack), X3
	VPADDQ  4*16(Stack), X3, X3

	VPADDD X0, X12, X12
	VPADDD X1, X13, X13
	VPADDD X2, X14, X14
	VPADDD X3, X15, X15
	VPADDQ 4*16(Stack), X3, X3
	VPADDD X0, X8, X8
	VPADDD X1, X9, X9
	VPADDD X2, X10, X10
	VPADDD X3, X11, X11
	VPADDQ 4*16(Stack), X3, X3
	VPADDD X0, X4, X4
	VPADDD X1, X5, X5
	VPADDD X2, X6, X6
	VPADDD X3, X7, X7
	VPADDQ 4*16(Stack), X3, X3

	XOR_AVX(Dst, Src, 64, X12, X13, X14, X15, X0)
	XOR_AVX(Dst, Src, 128, X8, X9, X10, X11, X0)
	VMOVDQA 0*16(Stack), X0 // Restore X0
	ADDQ    $192, Dst
	ADDQ    $192, Src
	SUBQ    $192, Len

	CMPQ Len, $64
	JL   BUFFER_KEYSTREAM

	XOR_AVX(Dst, Src, 0, X4, X5, X6, X7, X8)
	ADDQ $64, Dst
	ADDQ $64, Src
	SUBQ $64, Len
	JZ   DONE
	CMPQ Len, $64               // If Len <= 64 -> gen. only 64 byte keystream.
	JLE  GENERATE_KEYSTREAM_64
	CMPQ Len, $128              // If 64 < Len <= 128 -> gen. only 128 byte keystream.
	JLE  GENERATE_KEYSTREAM_128
	CMPQ Len, $192              // If Len > 192 -> repeat, otherwise Len > 128 && Len <= 192 -> gen. 192 byte keystream
	JG   GENERATE_KEYSTREAM_256

GENERATE_KEYSTREAM_192:
	VMOVDQA X0, X12
	VMOVDQA X1, X13
	VMOVDQA X2, X14
	VMOVDQA X3, X15
	VMOVDQA X0, X8
	VMOVDQA X1, X9
	VMOVDQA X2, X10
	VMOVDQA X3, X11
	VPADDQ  4*16(Stack), X11, X11
	VMOVDQA X0, X4
	VMOVDQA X1, X5
	VMOVDQA X2, X6
	VMOVDQA X11, X7
	VPADDQ  4*16(Stack), X7, X7
	MOVQ    Rounds, Tmp0

	VMOVDQA 6*16(Stack), X1 // Load 16 bit rotate-left constant
	VMOVDQA 7*16(Stack), X2 // Load 8 bit rotate-left constant

CHACHA_LOOP_192:
	CHACHA_QROUND_AVX(X12, X13, X14, X15, X0, X1, X2)
	CHACHA_QROUND_AVX(X8, X9, X10, X11, X0, X1, X2)
	CHACHA_QROUND_AVX(X4, X5, X6, X7, X0, X1, X2)
	CHACHA_SHUFFLE_AVX(X13, X14, X15)
	CHACHA_SHUFFLE_AVX(X9, X10, X11)
	CHACHA_SHUFFLE_AVX(X5, X6, X7)
	CHACHA_QROUND_AVX(X12, X13, X14, X15, X0, X1, X2)
	CHACHA_QROUND_AVX(X8, X9, X10, X11, X0, X1, X2)
	CHACHA_QROUND_AVX(X4, X5, X6, X7, X0, X1, X2)
	CHACHA_SHUFFLE_AVX(X15, X14, X13)
	CHACHA_SHUFFLE_AVX(X11, X10, X9)
	CHACHA_SHUFFLE_AVX(X7, X6, X5)
	SUBQ $2, Tmp0
	JNZ  CHACHA_LOOP_192

	VMOVDQA 0*16(Stack), X0     // Restore X0
	VMOVDQA 1*16(Stack), X1     // Restore X1
	VMOVDQA 2*16(Stack), X2     // Restore X2
	VPADDD  X0, X12, X12
	VPADDD  X1, X13, X13
	VPADDD  X2, X14, X14
	VPADDD  X3, X15, X15
	VPADDQ  4*16(Stack), X3, X3
	VPADDD  X0, X8, X8
	VPADDD  X1, X9, X9
	VPADDD  X2, X10, X10
	VPADDD  X3, X11, X11
	VPADDQ  4*16(Stack), X3, X3
	VPADDD  X0, X4, X4
	VPADDD  X1, X5, X5
	VPADDD  X2, X6, X6
	VPADDD  X3, X7, X7
	VPADDQ  4*16(Stack), X3, X3

	XOR_AVX(Dst, Src, 0, X12, X13, X14, X15, X0)
	XOR_AVX(Dst, Src, 64, X8, X9, X10, X11, X0)
	VMOVDQA 0*16(Stack), X0 // Restore X0
	ADDQ    $128, Dst
	ADDQ    $128, Src
	SUBQ    $128, Len

	CMPQ Len, $64
	JL   BUFFER_KEYSTREAM

	XOR_AVX(Dst, Src, 0, X4, X5, X6, X7, X8)
	ADDQ $64, Dst
	ADDQ $64, Src
	SUBQ $64, Len
	JZ   DONE
	CMPQ Len, $64              // If Len <= 64 -> gen. only 64 byte keystream.
	JLE  GENERATE_KEYSTREAM_64

GENERATE_KEYSTREAM_128:
	VMOVDQA X0, X8
	VMOVDQA X1, X9
	VMOVDQA X2, X10
	VMOVDQA X3, X11
	VMOVDQA X0, X4
	VMOVDQA X1, X5
	VMOVDQA X2, X6
	VMOVDQA X3, X7
	VPADDQ  4*16(Stack), X7, X7
	MOVQ    Rounds, Tmp0

	VMOVDQA 6*16(Stack), X13 // Load 16 bit rotate-left constant
	VMOVDQA 7*16(Stack), X14 // Load 8 bit rotate-left constant

CHACHA_LOOP_128:
	CHACHA_QROUND_AVX(X8, X9, X10, X11, X12, X13, X14)
	CHACHA_QROUND_AVX(X4, X5, X6, X7, X12, X13, X14)
	CHACHA_SHUFFLE_AVX(X9, X10, X11)
	CHACHA_SHUFFLE_AVX(X5, X6, X7)
	CHACHA_QROUND_AVX(X8, X9, X10, X11, X12, X13, X14)
	CHACHA_QROUND_AVX(X4, X5, X6, X7, X12, X13, X14)
	CHACHA_SHUFFLE_AVX(X11, X10, X9)
	CHACHA_SHUFFLE_AVX(X7, X6, X5)
	SUBQ $2, Tmp0
	JNZ  CHACHA_LOOP_128

	VPADDD X0, X8, X8
	VPADDD X1, X9, X9
	VPADDD X2, X10, X10
	VPADDD X3, X11, X11
	VPADDQ 4*16(Stack), X3, X3
	VPADDD X0, X4, X4
	VPADDD X1, X5, X5
	VPADDD X2, X6, X6
	VPADDD X3, X7, X7
	VPADDQ 4*16(Stack), X3, X3

	XOR_AVX(Dst, Src, 0, X8, X9, X10, X11, X12)
	ADDQ $64, Dst
	ADDQ $64, Src
	SUBQ $64, Len

	CMPQ Len, $64
	JL   BUFFER_KEYSTREAM

	XOR_AVX(Dst, Src, 0, X4, X5, X6, X7, X8)
	ADDQ $64, Dst
	ADDQ $64, Src
	SUBQ $64, Len
	JZ   DONE     // If Len == 0 -> DONE, otherwise Len <= 64 -> gen 64 byte keystream

GENERATE_KEYSTREAM_64:
	VMOVDQA X0, X4
	VMOVDQA X1, X5
	VMOVDQA X2, X6
	VMOVDQA X3, X7
	MOVQ    Rounds, Tmp0

	VMOVDQA 6*16(Stack), X9  // Load 16 bit rotate-left constant
	VMOVDQA 7*16(Stack), X10 // Load 8 bit rotate-left constant

CHACHA_LOOP_64:
	CHACHA_QROUND_AVX(X4, X5, X6, X7, X8, X9, X10)
	CHACHA_SHUFFLE_AVX(X5, X6, X7)
	CHACHA_QROUND_AVX(X4, X5, X6, X7, X8, X9, X10)
	CHACHA_SHUFFLE_AVX(X7, X6, X5)
	SUBQ $2, Tmp0
	JNZ  CHACHA_LOOP_64

	VPADDD X0, X4, X4
	VPADDD X1, X5, X5
	VPADDD X2, X6, X6
	VPADDD X3, X7, X7
	VPADDQ 4*16(Stack), X3, X3

	CMPQ Len, $64
	JL   BUFFER_KEYSTREAM

	XOR_AVX(Dst, Src, 0, X4, X5, X6, X7, X8)
	ADDQ $64, Src
	ADDQ $64, Dst
	SUBQ $64, Len
	JMP  DONE     // jump directly to DONE - there is no keystream to buffer, Len == 0 always true.

BUFFER_KEYSTREAM:
	VMOVDQU X4, 0*16(Buffer)
	VMOVDQU X5, 1*16(Buffer)
	VMOVDQU X6, 2*16(Buffer)
	VMOVDQU X7, 3*16(Buffer)
	MOVQ    Len, Tmp0
	FINALIZE(Dst, Src, Buffer, Tmp0, Tmp1, Tmp2)

DONE:
	MOVQ    SavedSP, Stack  // Restore stack pointer
	VMOVDQU X3, 3*16(State)
	VZEROUPPER
	MOVQ    Len, ret+72(FP)
	RET

#undef Dst
#undef Src
#undef Len
#undef Rounds
#undef Buffer
#undef State
#undef Stack
#undef SavedSP
#undef Tmp0
#undef Tmp1
#undef Tmp2
