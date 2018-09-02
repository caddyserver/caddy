// Copyright (c) 2018 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// +build 386,!gccgo,!appengine,!nacl amd64,!gccgo,!appengine,!nacl

// ROTL_SSE rotates all 4 32 bit values of the XMM register v
// left by n bits using SSE2 instructions (0 <= n <= 32).
// The XMM register t is used as a temp. register.
#define ROTL_SSE(n, t, v) \
	MOVO  v, t;       \
	PSLLL $n, t;      \
	PSRLL $(32-n), v; \
	PXOR  t, v

// ROTL_AVX rotates all 4/8 32 bit values of the AVX/AVX2 register v
// left by n bits using AVX/AVX2 instructions (0 <= n <= 32).
// The AVX/AVX2 register t is used as a temp. register.
#define ROTL_AVX(n, t, v) \
	VPSLLD $n, v, t;      \
	VPSRLD $(32-n), v, v; \
	VPXOR  v, t, v

// CHACHA_QROUND_SSE2 performs a ChaCha quarter-round using the
// 4 XMM registers v0, v1, v2 and v3. It uses only ROTL_SSE2 for
// rotations. The XMM register t is used as a temp. register.
#define CHACHA_QROUND_SSE2(v0, v1, v2, v3, t) \
	PADDL v1, v0;        \
	PXOR  v0, v3;        \
	ROTL_SSE(16, t, v3); \
	PADDL v3, v2;        \
	PXOR  v2, v1;        \
	ROTL_SSE(12, t, v1); \
	PADDL v1, v0;        \
	PXOR  v0, v3;        \
	ROTL_SSE(8, t, v3);  \
	PADDL v3, v2;        \
	PXOR  v2, v1;        \
	ROTL_SSE(7, t, v1)

// CHACHA_QROUND_SSSE3 performs a ChaCha quarter-round using the
// 4 XMM registers v0, v1, v2 and v3. It uses PSHUFB for 8/16 bit
// rotations. The XMM register t is used as a temp. register.
//
// r16 holds the PSHUFB constant for a 16 bit left rotate.
// r8 holds the PSHUFB constant for a 8 bit left rotate.
#define CHACHA_QROUND_SSSE3(v0, v1, v2, v3, t, r16, r8) \
	PADDL  v1, v0;       \
	PXOR   v0, v3;       \
	PSHUFB r16, v3;      \
	PADDL  v3, v2;       \
	PXOR   v2, v1;       \
	ROTL_SSE(12, t, v1); \
	PADDL  v1, v0;       \
	PXOR   v0, v3;       \
	PSHUFB r8, v3;       \
	PADDL  v3, v2;       \
	PXOR   v2, v1;       \
	ROTL_SSE(7, t, v1)

// CHACHA_QROUND_AVX performs a ChaCha quarter-round using the
// 4 AVX/AVX2 registers v0, v1, v2 and v3. It uses VPSHUFB for 8/16 bit
// rotations. The AVX/AVX2 register t is used as a temp. register.
//
// r16 holds the VPSHUFB constant for a 16 bit left rotate.
// r8 holds the VPSHUFB constant for a 8 bit left rotate.
#define CHACHA_QROUND_AVX(v0, v1, v2, v3, t, r16, r8) \
	VPADDD  v0, v1, v0;  \
	VPXOR   v3, v0, v3;  \
	VPSHUFB r16, v3, v3; \
	VPADDD  v2, v3, v2;  \
	VPXOR   v1, v2, v1;  \
	ROTL_AVX(12, t, v1); \
	VPADDD  v0, v1, v0;  \
	VPXOR   v3, v0, v3;  \
	VPSHUFB r8, v3, v3;  \
	VPADDD  v2, v3, v2;  \
	VPXOR   v1, v2, v1;  \
	ROTL_AVX(7, t, v1)

// CHACHA_SHUFFLE_SSE performs a ChaCha shuffle using the
// 3 XMM registers v1, v2 and v3. The inverse shuffle is
// performed by switching v1 and v3: CHACHA_SHUFFLE_SSE(v3, v2, v1).
#define CHACHA_SHUFFLE_SSE(v1, v2, v3) \
	PSHUFL $0x39, v1, v1; \
	PSHUFL $0x4E, v2, v2; \
	PSHUFL $0x93, v3, v3

// CHACHA_SHUFFLE_AVX performs a ChaCha shuffle using the
// 3 AVX/AVX2 registers v1, v2 and v3. The inverse shuffle is
// performed by switching v1 and v3: CHACHA_SHUFFLE_AVX(v3, v2, v1).
#define CHACHA_SHUFFLE_AVX(v1, v2, v3) \
	VPSHUFD $0x39, v1, v1; \
	VPSHUFD $0x4E, v2, v2; \
	VPSHUFD $0x93, v3, v3

// XOR_SSE extracts 4x16 byte vectors from src at
// off, xors all vectors with the corresponding XMM
// register (v0 - v3) and writes the result to dst
// at off.
// The XMM register t is used as a temp. register.
#define XOR_SSE(dst, src, off, v0, v1, v2, v3, t) \
	MOVOU 0+off(src), t;  \
	PXOR  v0, t;          \
	MOVOU t, 0+off(dst);  \
	MOVOU 16+off(src), t; \
	PXOR  v1, t;          \
	MOVOU t, 16+off(dst); \
	MOVOU 32+off(src), t; \
	PXOR  v2, t;          \
	MOVOU t, 32+off(dst); \
	MOVOU 48+off(src), t; \
	PXOR  v3, t;          \
	MOVOU t, 48+off(dst)

// XOR_AVX extracts 4x16 byte vectors from src at
// off, xors all vectors with the corresponding AVX
// register (v0 - v3) and writes the result to dst
// at off.
// The XMM register t is used as a temp. register.
#define XOR_AVX(dst, src, off, v0, v1, v2, v3, t) \
	VPXOR   0+off(src), v0, t;  \
	VMOVDQU t, 0+off(dst);      \
	VPXOR   16+off(src), v1, t; \
	VMOVDQU t, 16+off(dst);     \
	VPXOR   32+off(src), v2, t; \
	VMOVDQU t, 32+off(dst);     \
	VPXOR   48+off(src), v3, t; \
	VMOVDQU t, 48+off(dst)

#define XOR_AVX2(dst, src, off, v0, v1, v2, v3, t0, t1) \
	VMOVDQU    (0+off)(src), t0;  \
	VPERM2I128 $32, v1, v0, t1;   \
	VPXOR      t0, t1, t0;        \
	VMOVDQU    t0, (0+off)(dst);  \
	VMOVDQU    (32+off)(src), t0; \
	VPERM2I128 $32, v3, v2, t1;   \
	VPXOR      t0, t1, t0;        \
	VMOVDQU    t0, (32+off)(dst); \
	VMOVDQU    (64+off)(src), t0; \
	VPERM2I128 $49, v1, v0, t1;   \
	VPXOR      t0, t1, t0;        \
	VMOVDQU    t0, (64+off)(dst); \
	VMOVDQU    (96+off)(src), t0; \
	VPERM2I128 $49, v3, v2, t1;   \
	VPXOR      t0, t1, t0;        \
	VMOVDQU    t0, (96+off)(dst)

#define XOR_UPPER_AVX2(dst, src, off, v0, v1, v2, v3, t0, t1) \
	VMOVDQU    (0+off)(src), t0;  \
	VPERM2I128 $32, v1, v0, t1;   \
	VPXOR      t0, t1, t0;        \
	VMOVDQU    t0, (0+off)(dst);  \
	VMOVDQU    (32+off)(src), t0; \
	VPERM2I128 $32, v3, v2, t1;   \
	VPXOR      t0, t1, t0;        \
	VMOVDQU    t0, (32+off)(dst); \

#define EXTRACT_LOWER(dst, v0, v1, v2, v3, t0) \
	VPERM2I128 $49, v1, v0, t0; \
	VMOVDQU    t0, 0(dst);      \
	VPERM2I128 $49, v3, v2, t0; \
	VMOVDQU    t0, 32(dst)
