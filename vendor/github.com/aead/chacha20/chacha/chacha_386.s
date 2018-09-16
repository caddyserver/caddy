// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// +build 386,!gccgo,!appengine,!nacl

#include "const.s"
#include "macro.s"

// FINALIZE xors len bytes from src and block using
// the temp. registers t0 and t1 and writes the result
// to dst.
#define FINALIZE(dst, src, block, len, t0, t1) \
	XORL t0, t0;       \
	XORL t1, t1;       \
	FINALIZE_LOOP:;    \
	MOVB 0(src), t0;   \
	MOVB 0(block), t1; \
	XORL t0, t1;       \
	MOVB t1, 0(dst);   \
	INCL src;          \
	INCL block;        \
	INCL dst;          \
	DECL len;          \
	JG   FINALIZE_LOOP \

#define Dst DI
#define Nonce AX
#define Key BX
#define Rounds DX

// func hChaCha20SSE2(out *[32]byte, nonce *[16]byte, key *[32]byte)
TEXT ·hChaCha20SSE2(SB), 4, $0-12
	MOVL out+0(FP), Dst
	MOVL nonce+4(FP), Nonce
	MOVL key+8(FP), Key

	MOVOU ·sigma<>(SB), X0
	MOVOU 0*16(Key), X1
	MOVOU 1*16(Key), X2
	MOVOU 0*16(Nonce), X3
	MOVL  $20, Rounds

chacha_loop:
	CHACHA_QROUND_SSE2(X0, X1, X2, X3, X4)
	CHACHA_SHUFFLE_SSE(X1, X2, X3)
	CHACHA_QROUND_SSE2(X0, X1, X2, X3, X4)
	CHACHA_SHUFFLE_SSE(X3, X2, X1)
	SUBL $2, Rounds
	JNZ  chacha_loop

	MOVOU X0, 0*16(Dst)
	MOVOU X3, 1*16(Dst)
	RET

// func hChaCha20SSSE3(out *[32]byte, nonce *[16]byte, key *[32]byte)
TEXT ·hChaCha20SSSE3(SB), 4, $0-12
	MOVL out+0(FP), Dst
	MOVL nonce+4(FP), Nonce
	MOVL key+8(FP), Key

	MOVOU ·sigma<>(SB), X0
	MOVOU 0*16(Key), X1
	MOVOU 1*16(Key), X2
	MOVOU 0*16(Nonce), X3
	MOVL  $20, Rounds

	MOVOU ·rol16<>(SB), X5
	MOVOU ·rol8<>(SB), X6

chacha_loop:
	CHACHA_QROUND_SSSE3(X0, X1, X2, X3, X4, X5, X6)
	CHACHA_SHUFFLE_SSE(X1, X2, X3)
	CHACHA_QROUND_SSSE3(X0, X1, X2, X3, X4, X5, X6)
	CHACHA_SHUFFLE_SSE(X3, X2, X1)
	SUBL $2, Rounds
	JNZ  chacha_loop

	MOVOU X0, 0*16(Dst)
	MOVOU X3, 1*16(Dst)
	RET

#undef Dst
#undef Nonce
#undef Key
#undef Rounds

#define State AX
#define Dst DI
#define Src SI
#define Len DX
#define Tmp0 BX
#define Tmp1 BP

// func xorKeyStreamSSE2(dst, src []byte, block, state *[64]byte, rounds int) int
TEXT ·xorKeyStreamSSE2(SB), 4, $0-40
	MOVL dst_base+0(FP), Dst
	MOVL src_base+12(FP), Src
	MOVL state+28(FP), State
	MOVL src_len+16(FP), Len
	MOVL $0, ret+36(FP)       // Number of bytes written to the keystream buffer - 0 iff len mod 64 == 0

	MOVOU 0*16(State), X0
	MOVOU 1*16(State), X1
	MOVOU 2*16(State), X2
	MOVOU 3*16(State), X3
	TESTL Len, Len
	JZ    DONE

GENERATE_KEYSTREAM:
	MOVO X0, X4
	MOVO X1, X5
	MOVO X2, X6
	MOVO X3, X7
	MOVL rounds+32(FP), Tmp0

CHACHA_LOOP:
	CHACHA_QROUND_SSE2(X4, X5, X6, X7, X0)
	CHACHA_SHUFFLE_SSE(X5, X6, X7)
	CHACHA_QROUND_SSE2(X4, X5, X6, X7, X0)
	CHACHA_SHUFFLE_SSE(X7, X6, X5)
	SUBL $2, Tmp0
	JA   CHACHA_LOOP

	MOVOU 0*16(State), X0 // Restore X0 from state
	PADDL X0, X4
	PADDL X1, X5
	PADDL X2, X6
	PADDL X3, X7
	MOVOU ·one<>(SB), X0
	PADDQ X0, X3

	CMPL Len, $64
	JL   BUFFER_KEYSTREAM

	XOR_SSE(Dst, Src, 0, X4, X5, X6, X7, X0)
	MOVOU 0*16(State), X0    // Restore X0 from state
	ADDL  $64, Src
	ADDL  $64, Dst
	SUBL  $64, Len
	JZ    DONE
	JMP   GENERATE_KEYSTREAM // There is at least one more plaintext byte

BUFFER_KEYSTREAM:
	MOVL  block+24(FP), State
	MOVOU X4, 0(State)
	MOVOU X5, 16(State)
	MOVOU X6, 32(State)
	MOVOU X7, 48(State)
	MOVL  Len, ret+36(FP)     // Number of bytes written to the keystream buffer - 0 < Len < 64
	FINALIZE(Dst, Src, State, Len, Tmp0, Tmp1)

DONE:
	MOVL  state+28(FP), State
	MOVOU X3, 3*16(State)
	RET

#undef State
#undef Dst
#undef Src
#undef Len
#undef Tmp0
#undef Tmp1
