package utils

import (
	"bytes"
	"fmt"
	"io"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("float16", func() {
	for _, v := range []ByteOrder{LittleEndian, BigEndian} {
		bo := v
		name := "little endian"
		if bo == BigEndian {
			name = "big endian"
		}

		Context(fmt.Sprintf("in %s", name), func() {
			It("reads", func() {
				testcases := []struct {
					expected uint64
					binary   uint16
				}{
					// There are fewer decoding test cases because encoding truncates, and
					// decoding returns the smallest expansion.
					// Small numbers represent themselves.
					{0, 0},
					{1, 1},
					{2, 2},
					{3, 3},
					{4, 4},
					{5, 5},
					{6, 6},
					{7, 7},
					{15, 15},
					{31, 31},
					{42, 42},
					{123, 123},
					{1234, 1234},
					// Check transition through 2^11.
					{2046, 2046},
					{2047, 2047},
					{2048, 2048},
					{2049, 2049},
					// Running out of mantissa at 2^12.
					{4094, 4094},
					{4095, 4095},
					{4096, 4096},
					{4098, 4097},
					{4100, 4098},
					// Check transition through 2^13.
					{8190, 6143},
					{8192, 6144},
					{8196, 6145},
					// Half-way through the exponents.
					{0x7FF8000, 0x87FF},
					{0x8000000, 0x8800},
					{0xFFF0000, 0x8FFF},
					{0x10000000, 0x9000},
					// Transition into the largest exponent.
					{0x1FFE0000000, 0xF7FF},
					{0x20000000000, 0xF800},
					{0x20040000000, 0xF801},
					// Transition into the max value.
					{0x3FF80000000, 0xFFFE},
					{0x3FFC0000000, 0xFFFF},
				}
				for _, testcase := range testcases {
					b := &bytes.Buffer{}
					bo.WriteUint16(b, testcase.binary)
					val, err := bo.ReadUfloat16(b)
					Expect(err).NotTo(HaveOccurred())
					Expect(val).To(Equal(testcase.expected))
				}
			})

			It("errors on eof", func() {
				_, err := bo.ReadUfloat16(&bytes.Buffer{})
				Expect(err).To(MatchError(io.EOF))
			})

			It("writes", func() {
				testcases := []struct {
					decoded uint64
					encoded uint16
				}{
					// Small numbers represent themselves.
					{0, 0},
					{1, 1},
					{2, 2},
					{3, 3},
					{4, 4},
					{5, 5},
					{6, 6},
					{7, 7},
					{15, 15},
					{31, 31},
					{42, 42},
					{123, 123},
					{1234, 1234},
					// Check transition through 2^11.
					{2046, 2046},
					{2047, 2047},
					{2048, 2048},
					{2049, 2049},
					// Running out of mantissa at 2^12.
					{4094, 4094},
					{4095, 4095},
					{4096, 4096},
					{4097, 4096},
					{4098, 4097},
					{4099, 4097},
					{4100, 4098},
					{4101, 4098},
					// Check transition through 2^13.
					{8190, 6143},
					{8191, 6143},
					{8192, 6144},
					{8193, 6144},
					{8194, 6144},
					{8195, 6144},
					{8196, 6145},
					{8197, 6145},
					// Half-way through the exponents.
					{0x7FF8000, 0x87FF},
					{0x7FFFFFF, 0x87FF},
					{0x8000000, 0x8800},
					{0xFFF0000, 0x8FFF},
					{0xFFFFFFF, 0x8FFF},
					{0x10000000, 0x9000},
					// Transition into the largest exponent.
					{0x1FFFFFFFFFE, 0xF7FF},
					{0x1FFFFFFFFFF, 0xF7FF},
					{0x20000000000, 0xF800},
					{0x20000000001, 0xF800},
					{0x2003FFFFFFE, 0xF800},
					{0x2003FFFFFFF, 0xF800},
					{0x20040000000, 0xF801},
					{0x20040000001, 0xF801},
					// Transition into the max value and clamping.
					{0x3FF80000000, 0xFFFE},
					{0x3FFBFFFFFFF, 0xFFFE},
					{0x3FFC0000000, 0xFFFF},
					{0x3FFC0000001, 0xFFFF},
					{0x3FFFFFFFFFF, 0xFFFF},
					{0x40000000000, 0xFFFF},
					{0xFFFFFFFFFFFFFFFF, 0xFFFF},
				}
				for _, testcase := range testcases {
					b := &bytes.Buffer{}
					bo.WriteUfloat16(b, testcase.decoded)
					val, err := bo.ReadUint16(b)
					Expect(err).NotTo(HaveOccurred())
					Expect(val).To(Equal(testcase.encoded))
				}
			})
		})
	}
})
