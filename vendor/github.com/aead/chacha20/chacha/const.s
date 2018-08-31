// Copyright (c) 2018 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// +build 386,!gccgo,!appengine,!nacl amd64,!gccgo,!appengine,!nacl

#include "textflag.h"

DATA ·sigma<>+0x00(SB)/4, $0x61707865
DATA ·sigma<>+0x04(SB)/4, $0x3320646e
DATA ·sigma<>+0x08(SB)/4, $0x79622d32
DATA ·sigma<>+0x0C(SB)/4, $0x6b206574
GLOBL ·sigma<>(SB), (NOPTR+RODATA), $16 // The 4 ChaCha initialization constants

// SSE2/SSE3/AVX constants

DATA ·one<>+0x00(SB)/8, $1
DATA ·one<>+0x08(SB)/8, $0
GLOBL ·one<>(SB), (NOPTR+RODATA), $16 // The constant 1 as 128 bit value

DATA ·rol16<>+0x00(SB)/8, $0x0504070601000302
DATA ·rol16<>+0x08(SB)/8, $0x0D0C0F0E09080B0A
GLOBL ·rol16<>(SB), (NOPTR+RODATA), $16 // The PSHUFB 16 bit left rotate constant

DATA ·rol8<>+0x00(SB)/8, $0x0605040702010003
DATA ·rol8<>+0x08(SB)/8, $0x0E0D0C0F0A09080B
GLOBL ·rol8<>(SB), (NOPTR+RODATA), $16 // The PSHUFB 8 bit left rotate constant

// AVX2 constants

DATA ·one_AVX2<>+0x00(SB)/8, $0
DATA ·one_AVX2<>+0x08(SB)/8, $0
DATA ·one_AVX2<>+0x10(SB)/8, $1
DATA ·one_AVX2<>+0x18(SB)/8, $0
GLOBL ·one_AVX2<>(SB), (NOPTR+RODATA), $32 // The constant 1 as 256 bit value

DATA ·two_AVX2<>+0x00(SB)/8, $2
DATA ·two_AVX2<>+0x08(SB)/8, $0
DATA ·two_AVX2<>+0x10(SB)/8, $2
DATA ·two_AVX2<>+0x18(SB)/8, $0
GLOBL ·two_AVX2<>(SB), (NOPTR+RODATA), $32

DATA ·rol16_AVX2<>+0x00(SB)/8, $0x0504070601000302
DATA ·rol16_AVX2<>+0x08(SB)/8, $0x0D0C0F0E09080B0A
DATA ·rol16_AVX2<>+0x10(SB)/8, $0x0504070601000302
DATA ·rol16_AVX2<>+0x18(SB)/8, $0x0D0C0F0E09080B0A
GLOBL ·rol16_AVX2<>(SB), (NOPTR+RODATA), $32 // The VPSHUFB 16 bit left rotate constant

DATA ·rol8_AVX2<>+0x00(SB)/8, $0x0605040702010003
DATA ·rol8_AVX2<>+0x08(SB)/8, $0x0E0D0C0F0A09080B
DATA ·rol8_AVX2<>+0x10(SB)/8, $0x0605040702010003
DATA ·rol8_AVX2<>+0x18(SB)/8, $0x0E0D0C0F0A09080B
GLOBL ·rol8_AVX2<>(SB), (NOPTR+RODATA), $32 // The VPSHUFB 8 bit left rotate constant
