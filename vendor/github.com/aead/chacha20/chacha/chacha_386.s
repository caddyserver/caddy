// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// +build 386,!gccgo,!appengine,!nacl

#include "textflag.h"

DATA ·sigma<>+0x00(SB)/4, $0x61707865
DATA ·sigma<>+0x04(SB)/4, $0x3320646e
DATA ·sigma<>+0x08(SB)/4, $0x79622d32
DATA ·sigma<>+0x0C(SB)/4, $0x6b206574
GLOBL ·sigma<>(SB), (NOPTR+RODATA), $16

DATA ·one<>+0x00(SB)/8, $1
DATA ·one<>+0x08(SB)/8, $0
GLOBL ·one<>(SB), (NOPTR+RODATA), $16

DATA ·rol16<>+0x00(SB)/8, $0x0504070601000302
DATA ·rol16<>+0x08(SB)/8, $0x0D0C0F0E09080B0A
GLOBL ·rol16<>(SB), (NOPTR+RODATA), $16

DATA ·rol8<>+0x00(SB)/8, $0x0605040702010003
DATA ·rol8<>+0x08(SB)/8, $0x0E0D0C0F0A09080B
GLOBL ·rol8<>(SB), (NOPTR+RODATA), $16

#define ROTL_SSE2(n, t, v) \
	MOVO  v, t;       \
	PSLLL $n, t;      \
	PSRLL $(32-n), v; \
	PXOR  t, v

#define CHACHA_QROUND_SSE2(v0, v1, v2, v3, t0) \
	PADDL v1, v0;          \
	PXOR  v0, v3;          \
	ROTL_SSE2(16, t0, v3); \
	PADDL v3, v2;          \
	PXOR  v2, v1;          \
	ROTL_SSE2(12, t0, v1); \
	PADDL v1, v0;          \
	PXOR  v0, v3;          \
	ROTL_SSE2(8, t0, v3);  \
	PADDL v3, v2;          \
	PXOR  v2, v1;          \
	ROTL_SSE2(7, t0, v1)

#define CHACHA_QROUND_SSSE3(v0, v1, v2, v3, t0, r16, r8) \
	PADDL  v1, v0;         \
	PXOR   v0, v3;         \
	PSHUFB r16, v3;        \
	PADDL  v3, v2;         \
	PXOR   v2, v1;         \
	ROTL_SSE2(12, t0, v1); \
	PADDL  v1, v0;         \
	PXOR   v0, v3;         \
	PSHUFB r8, v3;         \
	PADDL  v3, v2;         \
	PXOR   v2, v1;         \
	ROTL_SSE2(7, t0, v1)

#define CHACHA_SHUFFLE(v1, v2, v3) \
	PSHUFL $0x39, v1, v1; \
	PSHUFL $0x4E, v2, v2; \
	PSHUFL $0x93, v3, v3

#define XOR(dst, src, off, v0, v1, v2, v3, t0) \
	MOVOU 0+off(src), t0;  \
	PXOR  v0, t0;          \
	MOVOU t0, 0+off(dst);  \
	MOVOU 16+off(src), t0; \
	PXOR  v1, t0;          \
	MOVOU t0, 16+off(dst); \
	MOVOU 32+off(src), t0; \
	PXOR  v2, t0;          \
	MOVOU t0, 32+off(dst); \
	MOVOU 48+off(src), t0; \
	PXOR  v3, t0;          \
	MOVOU t0, 48+off(dst)

#define FINALIZE(dst, src, block, len, t0, t1) \
	XORL      t0, t0;       \
	XORL      t1, t1;       \
	finalize:               \
	MOVB      0(src), t0;   \
	MOVB      0(block), t1; \
	XORL      t0, t1;       \
	MOVB      t1, 0(dst);   \
	INCL      src;          \
	INCL      block;        \
	INCL      dst;          \
	DECL      len;          \
	JA        finalize      \

// func xorKeyStreamSSE2(dst, src []byte, block, state *[64]byte, rounds int) int
TEXT ·xorKeyStreamSSE2(SB), 4, $0-40
	MOVL dst_base+0(FP), DI
	MOVL src_base+12(FP), SI
	MOVL src_len+16(FP), CX
	MOVL state+28(FP), AX
	MOVL rounds+32(FP), DX

	MOVOU 0(AX), X0
	MOVOU 16(AX), X1
	MOVOU 32(AX), X2
	MOVOU 48(AX), X3

	TESTL CX, CX
	JZ    done

at_least_64:
	MOVO X0, X4
	MOVO X1, X5
	MOVO X2, X6
	MOVO X3, X7

	MOVL DX, BX

chacha_loop:
	CHACHA_QROUND_SSE2(X4, X5, X6, X7, X0)
	CHACHA_SHUFFLE(X5, X6, X7)
	CHACHA_QROUND_SSE2(X4, X5, X6, X7, X0)
	CHACHA_SHUFFLE(X7, X6, X5)
	SUBL $2, BX
	JA   chacha_loop

	MOVOU 0(AX), X0
	PADDL X0, X4
	PADDL X1, X5
	PADDL X2, X6
	PADDL X3, X7
	MOVOU ·one<>(SB), X0
	PADDQ X0, X3

	CMPL CX, $64
	JB   less_than_64

	XOR(DI, SI, 0, X4, X5, X6, X7, X0)
	MOVOU 0(AX), X0
	ADDL  $64, SI
	ADDL  $64, DI
	SUBL  $64, CX
	JNZ   at_least_64

less_than_64:
	MOVL  CX, BP
	TESTL BP, BP
	JZ    done

	MOVL  block+24(FP), BX
	MOVOU X4, 0(BX)
	MOVOU X5, 16(BX)
	MOVOU X6, 32(BX)
	MOVOU X7, 48(BX)
	FINALIZE(DI, SI, BX, BP, AX, DX)

done:
	MOVL  state+28(FP), AX
	MOVOU X3, 48(AX)
	MOVL  CX, ret+36(FP)
	RET

// func xorKeyStreamSSSE3(dst, src []byte, block, state *[64]byte, rounds int) int
TEXT ·xorKeyStreamSSSE3(SB), 4, $64-40
	MOVL dst_base+0(FP), DI
	MOVL src_base+12(FP), SI
	MOVL src_len+16(FP), CX
	MOVL state+28(FP), AX
	MOVL rounds+32(FP), DX

	MOVOU 48(AX), X3
	TESTL CX, CX
	JZ    done

	MOVL SP, BP
	ADDL $16, SP
	ANDL $-16, SP

	MOVOU ·one<>(SB), X0
	MOVOU 16(AX), X1
	MOVOU 32(AX), X2
	MOVO  X0, 0(SP)
	MOVO  X1, 16(SP)
	MOVO  X2, 32(SP)

	MOVOU 0(AX), X0
	MOVOU ·rol16<>(SB), X1
	MOVOU ·rol8<>(SB), X2

at_least_64:
	MOVO X0, X4
	MOVO 16(SP), X5
	MOVO 32(SP), X6
	MOVO X3, X7

	MOVL DX, BX

chacha_loop:
	CHACHA_QROUND_SSSE3(X4, X5, X6, X7, X0, X1, X2)
	CHACHA_SHUFFLE(X5, X6, X7)
	CHACHA_QROUND_SSSE3(X4, X5, X6, X7, X0, X1, X2)
	CHACHA_SHUFFLE(X7, X6, X5)
	SUBL $2, BX
	JA   chacha_loop

	MOVOU 0(AX), X0
	PADDL X0, X4
	PADDL 16(SP), X5
	PADDL 32(SP), X6
	PADDL X3, X7
	PADDQ 0(SP), X3

	CMPL CX, $64
	JB   less_than_64

	XOR(DI, SI, 0, X4, X5, X6, X7, X0)
	MOVOU 0(AX), X0
	ADDL  $64, SI
	ADDL  $64, DI
	SUBL  $64, CX
	JNZ   at_least_64

less_than_64:
	MOVL  BP, SP
	MOVL  CX, BP
	TESTL BP, BP
	JE    done

	MOVL  block+24(FP), BX
	MOVOU X4, 0(BX)
	MOVOU X5, 16(BX)
	MOVOU X6, 32(BX)
	MOVOU X7, 48(BX)
	FINALIZE(DI, SI, BX, BP, AX, DX)

done:
	MOVL  state+28(FP), AX
	MOVOU X3, 48(AX)
	MOVL  CX, ret+36(FP)
	RET

// func supportsSSE2() bool
TEXT ·supportsSSE2(SB), NOSPLIT, $0-1
	XORL AX, AX
	INCL AX
	CPUID
	SHRL $26, DX
	ANDL $1, DX
	MOVB DX, ret+0(FP)
	RET

// func supportsSSSE3() bool
TEXT ·supportsSSSE3(SB), NOSPLIT, $0-1
	XORL AX, AX
	INCL AX
	CPUID
	SHRL $9, CX
	ANDL $1, CX
	MOVB CX, ret+0(FP)
	RET

// func hChaCha20SSE2(out *[32]byte, nonce *[16]byte, key *[32]byte)
TEXT ·hChaCha20SSE2(SB), 4, $0-12
	MOVL out+0(FP), DI
	MOVL nonce+4(FP), AX
	MOVL key+8(FP), BX

	MOVOU ·sigma<>(SB), X0
	MOVOU 0(BX), X1
	MOVOU 16(BX), X2
	MOVOU 0(AX), X3

	MOVL $20, CX

chacha_loop:
	CHACHA_QROUND_SSE2(X0, X1, X2, X3, X4)
	CHACHA_SHUFFLE(X1, X2, X3)
	CHACHA_QROUND_SSE2(X0, X1, X2, X3, X4)
	CHACHA_SHUFFLE(X3, X2, X1)
	SUBL $2, CX
	JNZ  chacha_loop

	MOVOU X0, 0(DI)
	MOVOU X3, 16(DI)
	RET

// func hChaCha20SSSE3(out *[32]byte, nonce *[16]byte, key *[32]byte)
TEXT ·hChaCha20SSSE3(SB), 4, $0-12
	MOVL out+0(FP), DI
	MOVL nonce+4(FP), AX
	MOVL key+8(FP), BX

	MOVOU ·sigma<>(SB), X0
	MOVOU 0(BX), X1
	MOVOU 16(BX), X2
	MOVOU 0(AX), X3
	MOVOU ·rol16<>(SB), X5
	MOVOU ·rol8<>(SB), X6

	MOVL $20, CX

chacha_loop:
	CHACHA_QROUND_SSSE3(X0, X1, X2, X3, X4, X5, X6)
	CHACHA_SHUFFLE(X1, X2, X3)
	CHACHA_QROUND_SSSE3(X0, X1, X2, X3, X4, X5, X6)
	CHACHA_SHUFFLE(X3, X2, X1)
	SUBL $2, CX
	JNZ  chacha_loop

	MOVOU X0, 0(DI)
	MOVOU X3, 16(DI)
	RET
