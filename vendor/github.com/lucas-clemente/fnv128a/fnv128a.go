// Package fnv128a implements FNV-1 and FNV-1a, non-cryptographic hash functions
// created by Glenn Fowler, Landon Curt Noll, and Phong Vo.
// See https://en.wikipedia.org/wiki/Fowler-Noll-Vo_hash_function.
//
// Write() algorithm taken and modified from github.com/romain-jacotin/quic
package fnv128a

import "hash"

// Hash128 is the common interface implemented by all 128-bit hash functions.
type Hash128 interface {
	hash.Hash
	Sum128() (uint64, uint64)
}

type sum128a struct {
	v0, v1, v2, v3 uint64
}

var _ Hash128 = &sum128a{}

// New1 returns a new 128-bit FNV-1a hash.Hash.
func New() Hash128 {
	s := &sum128a{}
	s.Reset()
	return s
}

func (s *sum128a) Reset() {
	s.v0 = 0x6295C58D
	s.v1 = 0x62B82175
	s.v2 = 0x07BB0142
	s.v3 = 0x6C62272E
}

func (s *sum128a) Sum128() (uint64, uint64) {
	return s.v3<<32 | s.v2, s.v1<<32 | s.v0
}

func (s *sum128a) Write(data []byte) (int, error) {
	var t0, t1, t2, t3 uint64
	const fnv128PrimeLow = 0x0000013B
	const fnv128PrimeShift = 24

	for _, v := range data {
		// xor the bottom with the current octet
		s.v0 ^= uint64(v)

		// multiply by the 128 bit FNV magic prime mod 2^128
		// fnv_prime	= 309485009821345068724781371 (decimal)
		// 				= 0x0000000001000000000000000000013B (hexadecimal)
		// 				= 0x00000000 	0x01000000 				0x00000000	0x0000013B (in 4*32 words)
		//				= 0x0			1<<fnv128PrimeShift	0x0			fnv128PrimeLow
		//
		// fnv128PrimeLow = 0x0000013B
		// fnv128PrimeShift = 24

		// multiply by the lowest order digit base 2^32 and by the other non-zero digit
		t0 = s.v0 * fnv128PrimeLow
		t1 = s.v1 * fnv128PrimeLow
		t2 = s.v2*fnv128PrimeLow + s.v0<<fnv128PrimeShift
		t3 = s.v3*fnv128PrimeLow + s.v1<<fnv128PrimeShift

		// propagate carries
		t1 += (t0 >> 32)
		t2 += (t1 >> 32)
		t3 += (t2 >> 32)

		s.v0 = t0 & 0xffffffff
		s.v1 = t1 & 0xffffffff
		s.v2 = t2 & 0xffffffff
		s.v3 = t3 // & 0xffffffff
		// Doing a s.v3 &= 0xffffffff is not really needed since it simply
		// removes multiples of 2^128.  We can discard these excess bits
		// outside of the loop when writing the hash in Little Endian.
	}

	return len(data), nil
}

func (s *sum128a) Size() int { return 16 }

func (s *sum128a) BlockSize() int { return 1 }

func (s *sum128a) Sum(in []byte) []byte {
	panic("FNV: not supported")
}
