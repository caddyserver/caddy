// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package chacha

import "encoding/binary"

var sigma = [4]uint32{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}

func xorKeyStreamGeneric(dst, src []byte, block, state *[64]byte, rounds int) int {
	for len(src) >= 64 {
		chachaGeneric(block, state, rounds)

		for i, v := range block {
			dst[i] = src[i] ^ v
		}
		src = src[64:]
		dst = dst[64:]
	}

	n := len(src)
	if n > 0 {
		chachaGeneric(block, state, rounds)
		for i, v := range src {
			dst[i] = v ^ block[i]
		}
	}
	return n
}

func chachaGeneric(dst *[64]byte, state *[64]byte, rounds int) {
	v00 := binary.LittleEndian.Uint32(state[0:])
	v01 := binary.LittleEndian.Uint32(state[4:])
	v02 := binary.LittleEndian.Uint32(state[8:])
	v03 := binary.LittleEndian.Uint32(state[12:])
	v04 := binary.LittleEndian.Uint32(state[16:])
	v05 := binary.LittleEndian.Uint32(state[20:])
	v06 := binary.LittleEndian.Uint32(state[24:])
	v07 := binary.LittleEndian.Uint32(state[28:])
	v08 := binary.LittleEndian.Uint32(state[32:])
	v09 := binary.LittleEndian.Uint32(state[36:])
	v10 := binary.LittleEndian.Uint32(state[40:])
	v11 := binary.LittleEndian.Uint32(state[44:])
	v12 := binary.LittleEndian.Uint32(state[48:])
	v13 := binary.LittleEndian.Uint32(state[52:])
	v14 := binary.LittleEndian.Uint32(state[56:])
	v15 := binary.LittleEndian.Uint32(state[60:])

	s00, s01, s02, s03, s04, s05, s06, s07 := v00, v01, v02, v03, v04, v05, v06, v07
	s08, s09, s10, s11, s12, s13, s14, s15 := v08, v09, v10, v11, v12, v13, v14, v15

	for i := 0; i < rounds; i += 2 {
		v00 += v04
		v12 ^= v00
		v12 = (v12 << 16) | (v12 >> 16)
		v08 += v12
		v04 ^= v08
		v04 = (v04 << 12) | (v04 >> 20)
		v00 += v04
		v12 ^= v00
		v12 = (v12 << 8) | (v12 >> 24)
		v08 += v12
		v04 ^= v08
		v04 = (v04 << 7) | (v04 >> 25)
		v01 += v05
		v13 ^= v01
		v13 = (v13 << 16) | (v13 >> 16)
		v09 += v13
		v05 ^= v09
		v05 = (v05 << 12) | (v05 >> 20)
		v01 += v05
		v13 ^= v01
		v13 = (v13 << 8) | (v13 >> 24)
		v09 += v13
		v05 ^= v09
		v05 = (v05 << 7) | (v05 >> 25)
		v02 += v06
		v14 ^= v02
		v14 = (v14 << 16) | (v14 >> 16)
		v10 += v14
		v06 ^= v10
		v06 = (v06 << 12) | (v06 >> 20)
		v02 += v06
		v14 ^= v02
		v14 = (v14 << 8) | (v14 >> 24)
		v10 += v14
		v06 ^= v10
		v06 = (v06 << 7) | (v06 >> 25)
		v03 += v07
		v15 ^= v03
		v15 = (v15 << 16) | (v15 >> 16)
		v11 += v15
		v07 ^= v11
		v07 = (v07 << 12) | (v07 >> 20)
		v03 += v07
		v15 ^= v03
		v15 = (v15 << 8) | (v15 >> 24)
		v11 += v15
		v07 ^= v11
		v07 = (v07 << 7) | (v07 >> 25)
		v00 += v05
		v15 ^= v00
		v15 = (v15 << 16) | (v15 >> 16)
		v10 += v15
		v05 ^= v10
		v05 = (v05 << 12) | (v05 >> 20)
		v00 += v05
		v15 ^= v00
		v15 = (v15 << 8) | (v15 >> 24)
		v10 += v15
		v05 ^= v10
		v05 = (v05 << 7) | (v05 >> 25)
		v01 += v06
		v12 ^= v01
		v12 = (v12 << 16) | (v12 >> 16)
		v11 += v12
		v06 ^= v11
		v06 = (v06 << 12) | (v06 >> 20)
		v01 += v06
		v12 ^= v01
		v12 = (v12 << 8) | (v12 >> 24)
		v11 += v12
		v06 ^= v11
		v06 = (v06 << 7) | (v06 >> 25)
		v02 += v07
		v13 ^= v02
		v13 = (v13 << 16) | (v13 >> 16)
		v08 += v13
		v07 ^= v08
		v07 = (v07 << 12) | (v07 >> 20)
		v02 += v07
		v13 ^= v02
		v13 = (v13 << 8) | (v13 >> 24)
		v08 += v13
		v07 ^= v08
		v07 = (v07 << 7) | (v07 >> 25)
		v03 += v04
		v14 ^= v03
		v14 = (v14 << 16) | (v14 >> 16)
		v09 += v14
		v04 ^= v09
		v04 = (v04 << 12) | (v04 >> 20)
		v03 += v04
		v14 ^= v03
		v14 = (v14 << 8) | (v14 >> 24)
		v09 += v14
		v04 ^= v09
		v04 = (v04 << 7) | (v04 >> 25)
	}

	v00 += s00
	v01 += s01
	v02 += s02
	v03 += s03
	v04 += s04
	v05 += s05
	v06 += s06
	v07 += s07
	v08 += s08
	v09 += s09
	v10 += s10
	v11 += s11
	v12 += s12
	v13 += s13
	v14 += s14
	v15 += s15

	s12++
	binary.LittleEndian.PutUint32(state[48:], s12)
	if s12 == 0 { // indicates overflow
		s13++
		binary.LittleEndian.PutUint32(state[52:], s13)
	}

	binary.LittleEndian.PutUint32(dst[0:], v00)
	binary.LittleEndian.PutUint32(dst[4:], v01)
	binary.LittleEndian.PutUint32(dst[8:], v02)
	binary.LittleEndian.PutUint32(dst[12:], v03)
	binary.LittleEndian.PutUint32(dst[16:], v04)
	binary.LittleEndian.PutUint32(dst[20:], v05)
	binary.LittleEndian.PutUint32(dst[24:], v06)
	binary.LittleEndian.PutUint32(dst[28:], v07)
	binary.LittleEndian.PutUint32(dst[32:], v08)
	binary.LittleEndian.PutUint32(dst[36:], v09)
	binary.LittleEndian.PutUint32(dst[40:], v10)
	binary.LittleEndian.PutUint32(dst[44:], v11)
	binary.LittleEndian.PutUint32(dst[48:], v12)
	binary.LittleEndian.PutUint32(dst[52:], v13)
	binary.LittleEndian.PutUint32(dst[56:], v14)
	binary.LittleEndian.PutUint32(dst[60:], v15)
}

func hChaCha20Generic(out *[32]byte, nonce *[16]byte, key *[32]byte) {
	v00 := sigma[0]
	v01 := sigma[1]
	v02 := sigma[2]
	v03 := sigma[3]
	v04 := binary.LittleEndian.Uint32(key[0:])
	v05 := binary.LittleEndian.Uint32(key[4:])
	v06 := binary.LittleEndian.Uint32(key[8:])
	v07 := binary.LittleEndian.Uint32(key[12:])
	v08 := binary.LittleEndian.Uint32(key[16:])
	v09 := binary.LittleEndian.Uint32(key[20:])
	v10 := binary.LittleEndian.Uint32(key[24:])
	v11 := binary.LittleEndian.Uint32(key[28:])
	v12 := binary.LittleEndian.Uint32(nonce[0:])
	v13 := binary.LittleEndian.Uint32(nonce[4:])
	v14 := binary.LittleEndian.Uint32(nonce[8:])
	v15 := binary.LittleEndian.Uint32(nonce[12:])

	for i := 0; i < 20; i += 2 {
		v00 += v04
		v12 ^= v00
		v12 = (v12 << 16) | (v12 >> 16)
		v08 += v12
		v04 ^= v08
		v04 = (v04 << 12) | (v04 >> 20)
		v00 += v04
		v12 ^= v00
		v12 = (v12 << 8) | (v12 >> 24)
		v08 += v12
		v04 ^= v08
		v04 = (v04 << 7) | (v04 >> 25)
		v01 += v05
		v13 ^= v01
		v13 = (v13 << 16) | (v13 >> 16)
		v09 += v13
		v05 ^= v09
		v05 = (v05 << 12) | (v05 >> 20)
		v01 += v05
		v13 ^= v01
		v13 = (v13 << 8) | (v13 >> 24)
		v09 += v13
		v05 ^= v09
		v05 = (v05 << 7) | (v05 >> 25)
		v02 += v06
		v14 ^= v02
		v14 = (v14 << 16) | (v14 >> 16)
		v10 += v14
		v06 ^= v10
		v06 = (v06 << 12) | (v06 >> 20)
		v02 += v06
		v14 ^= v02
		v14 = (v14 << 8) | (v14 >> 24)
		v10 += v14
		v06 ^= v10
		v06 = (v06 << 7) | (v06 >> 25)
		v03 += v07
		v15 ^= v03
		v15 = (v15 << 16) | (v15 >> 16)
		v11 += v15
		v07 ^= v11
		v07 = (v07 << 12) | (v07 >> 20)
		v03 += v07
		v15 ^= v03
		v15 = (v15 << 8) | (v15 >> 24)
		v11 += v15
		v07 ^= v11
		v07 = (v07 << 7) | (v07 >> 25)
		v00 += v05
		v15 ^= v00
		v15 = (v15 << 16) | (v15 >> 16)
		v10 += v15
		v05 ^= v10
		v05 = (v05 << 12) | (v05 >> 20)
		v00 += v05
		v15 ^= v00
		v15 = (v15 << 8) | (v15 >> 24)
		v10 += v15
		v05 ^= v10
		v05 = (v05 << 7) | (v05 >> 25)
		v01 += v06
		v12 ^= v01
		v12 = (v12 << 16) | (v12 >> 16)
		v11 += v12
		v06 ^= v11
		v06 = (v06 << 12) | (v06 >> 20)
		v01 += v06
		v12 ^= v01
		v12 = (v12 << 8) | (v12 >> 24)
		v11 += v12
		v06 ^= v11
		v06 = (v06 << 7) | (v06 >> 25)
		v02 += v07
		v13 ^= v02
		v13 = (v13 << 16) | (v13 >> 16)
		v08 += v13
		v07 ^= v08
		v07 = (v07 << 12) | (v07 >> 20)
		v02 += v07
		v13 ^= v02
		v13 = (v13 << 8) | (v13 >> 24)
		v08 += v13
		v07 ^= v08
		v07 = (v07 << 7) | (v07 >> 25)
		v03 += v04
		v14 ^= v03
		v14 = (v14 << 16) | (v14 >> 16)
		v09 += v14
		v04 ^= v09
		v04 = (v04 << 12) | (v04 >> 20)
		v03 += v04
		v14 ^= v03
		v14 = (v14 << 8) | (v14 >> 24)
		v09 += v14
		v04 ^= v09
		v04 = (v04 << 7) | (v04 >> 25)
	}

	binary.LittleEndian.PutUint32(out[0:], v00)
	binary.LittleEndian.PutUint32(out[4:], v01)
	binary.LittleEndian.PutUint32(out[8:], v02)
	binary.LittleEndian.PutUint32(out[12:], v03)
	binary.LittleEndian.PutUint32(out[16:], v12)
	binary.LittleEndian.PutUint32(out[20:], v13)
	binary.LittleEndian.PutUint32(out[24:], v14)
	binary.LittleEndian.PutUint32(out[28:], v15)
}
