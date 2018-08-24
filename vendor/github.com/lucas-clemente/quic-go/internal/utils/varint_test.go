package utils

import (
	"bytes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Varint encoding / decoding", func() {
	Context("decoding", func() {
		It("reads a 1 byte number", func() {
			b := bytes.NewReader([]byte{25}) // 00011001
			val, err := ReadVarInt(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(val).To(Equal(uint64(25)))
			Expect(b.Len()).To(BeZero())
		})

		It("reads a number that is encoded too long", func() {
			b := bytes.NewReader([]byte{0x40, 0x25}) // first byte: 01000000
			val, err := ReadVarInt(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(val).To(Equal(uint64(37)))
			Expect(b.Len()).To(BeZero())
		})

		It("reads a 2 byte number", func() {
			b := bytes.NewReader([]byte{0x7b, 0xbd}) // first byte: 01111011
			val, err := ReadVarInt(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(val).To(Equal(uint64(15293)))
			Expect(b.Len()).To(BeZero())
		})

		It("reads a 4 byte number", func() {
			b := bytes.NewReader([]byte{0x9d, 0x7f, 0x3e, 0x7d}) // first byte: 10011011
			val, err := ReadVarInt(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(val).To(Equal(uint64(494878333)))
			Expect(b.Len()).To(BeZero())
		})

		It("reads an 8 byte number", func() {
			b := bytes.NewReader([]byte{0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c}) // first byte: 10000010
			val, err := ReadVarInt(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(val).To(Equal(uint64(151288809941952652)))
			Expect(b.Len()).To(BeZero())
		})
	})

	Context("encoding", func() {
		It("writes a 1 byte number", func() {
			b := &bytes.Buffer{}
			WriteVarInt(b, 37)
			Expect(b.Bytes()).To(Equal([]byte{0x25}))
		})

		It("writes the maximum 1 byte number in 1 byte", func() {
			b := &bytes.Buffer{}
			WriteVarInt(b, maxVarInt1)
			Expect(b.Bytes()).To(Equal([]byte{0x3f /* 00111111 */}))
		})

		It("writes the minimum 2 byte number in 2 bytes", func() {
			b := &bytes.Buffer{}
			WriteVarInt(b, maxVarInt1+1)
			Expect(b.Bytes()).To(Equal([]byte{0x40, maxVarInt1 + 1}))
		})

		It("writes a 2 byte number", func() {
			b := &bytes.Buffer{}
			WriteVarInt(b, 15293)
			Expect(b.Bytes()).To(Equal([]byte{0x7b, 0xbd}))
		})

		It("writes the maximum 2 byte number in 2 bytes", func() {
			b := &bytes.Buffer{}
			WriteVarInt(b, maxVarInt2)
			Expect(b.Bytes()).To(Equal([]byte{0x7f /* 01111111 */, 0xff}))
		})

		It("writes the minimum 4 byte number in 4 bytes", func() {
			b := &bytes.Buffer{}
			WriteVarInt(b, maxVarInt2+1)
			Expect(b.Len()).To(Equal(4))
			num, err := ReadVarInt(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(num).To(Equal(uint64(maxVarInt2 + 1)))
		})

		It("writes a 4 byte number", func() {
			b := &bytes.Buffer{}
			WriteVarInt(b, 494878333)
			Expect(b.Bytes()).To(Equal([]byte{0x9d, 0x7f, 0x3e, 0x7d}))
		})

		It("writes the maximum 4 byte number in 4 bytes", func() {
			b := &bytes.Buffer{}
			WriteVarInt(b, maxVarInt4)
			Expect(b.Bytes()).To(Equal([]byte{0xbf /* 10111111 */, 0xff, 0xff, 0xff}))
		})

		It("writes the minimum 8 byte number in 8 bytes", func() {
			b := &bytes.Buffer{}
			WriteVarInt(b, maxVarInt4+1)
			Expect(b.Len()).To(Equal(8))
			num, err := ReadVarInt(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(num).To(Equal(uint64(maxVarInt4 + 1)))
		})

		It("writes an 8 byte number", func() {
			b := &bytes.Buffer{}
			WriteVarInt(b, 151288809941952652)
			Expect(b.Bytes()).To(Equal([]byte{0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c}))
		})

		It("writes the maximum 8 byte number in 8 bytes", func() {
			b := &bytes.Buffer{}
			WriteVarInt(b, maxVarInt8)
			Expect(b.Bytes()).To(Equal([]byte{0xff /* 11111111 */, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}))
		})

		It("panics when given a too large number (> 62 bit)", func() {
			b := &bytes.Buffer{}
			Expect(func() { WriteVarInt(b, maxVarInt8+1) }).Should(Panic())
		})
	})

	Context("determining the length needed for encoding", func() {
		It("for numbers that need 1 byte", func() {
			Expect(VarIntLen(0)).To(BeEquivalentTo(1))
			Expect(VarIntLen(maxVarInt1)).To(BeEquivalentTo(1))
		})

		It("for numbers that need 2 bytes", func() {
			Expect(VarIntLen(maxVarInt1 + 1)).To(BeEquivalentTo(2))
			Expect(VarIntLen(maxVarInt2)).To(BeEquivalentTo(2))
		})

		It("for numbers that need 4 bytes", func() {
			Expect(VarIntLen(maxVarInt2 + 1)).To(BeEquivalentTo(4))
			Expect(VarIntLen(maxVarInt4)).To(BeEquivalentTo(4))
		})

		It("for numbers that need 8 bytes", func() {
			Expect(VarIntLen(maxVarInt4 + 1)).To(BeEquivalentTo(8))
			Expect(VarIntLen(maxVarInt8)).To(BeEquivalentTo(8))
		})

		It("panics when given a too large number (> 62 bit)", func() {
			Expect(func() { VarIntLen(maxVarInt8 + 1) }).Should(Panic())
		})
	})
})
