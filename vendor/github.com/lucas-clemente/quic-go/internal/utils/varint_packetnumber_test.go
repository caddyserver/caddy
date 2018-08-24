package utils

import (
	"bytes"
	"io"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Varint packet number encoding / decoding", func() {
	Context("Decoding", func() {
		It("reads a 1 byte number", func() {
			b := bytes.NewReader([]byte{0x19}) // 00011001
			p, len, err := ReadVarIntPacketNumber(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(len).To(Equal(protocol.PacketNumberLen1))
			Expect(p).To(Equal(protocol.PacketNumber(0x19)))
		})

		It("errors when given an empty reader", func() {
			_, _, err := ReadVarIntPacketNumber(bytes.NewReader(nil))
			Expect(err).To(MatchError(io.EOF))
		})

		It("reads a 2 byte number", func() {
			b := bytes.NewReader([]byte{0xb7, 0x19}) // first byte: 10110111
			p, len, err := ReadVarIntPacketNumber(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(len).To(Equal(protocol.PacketNumberLen2))
			Expect(p).To(Equal(protocol.PacketNumber(0x3719)))
		})

		It("errors on EOF when reading a 2 byte number", func() {
			b := bytes.NewReader([]byte{0xb7}) // first byte: 10110111
			_, _, err := ReadVarIntPacketNumber(b)
			Expect(err).To(MatchError(io.EOF))
		})

		It("reads a 4 byte number", func() {
			b := bytes.NewReader([]byte{0xe5, 0x89, 0xfa, 0x19}) // first byte: 11100101
			p, len, err := ReadVarIntPacketNumber(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(len).To(Equal(protocol.PacketNumberLen4))
			Expect(p).To(Equal(protocol.PacketNumber(0x2589fa19)))
		})

		It("errors on EOF after the 3rd byte when reading a 4 byte number", func() {
			b := bytes.NewReader([]byte{0xe5, 0x89}) // first byte: 11100101
			_, _, err := ReadVarIntPacketNumber(b)
			Expect(err).To(MatchError(io.EOF))
		})

		It("errors on EOF after the 4th byte when reading a 4 byte number", func() {
			b := bytes.NewReader([]byte{0xe5, 0x89, 0xfa}) // first byte: 11100101
			_, _, err := ReadVarIntPacketNumber(b)
			Expect(err).To(MatchError(io.EOF))
		})
	})

	Context("Encoding", func() {
		It("writes a 1 byte packet number", func() {
			b := &bytes.Buffer{}
			err := WriteVarIntPacketNumber(b, 0x42, protocol.PacketNumberLen1)
			Expect(err).ToNot(HaveOccurred())
			Expect(b.Len()).To(Equal(1))
			p, len, err := ReadVarIntPacketNumber(bytes.NewReader(b.Bytes()))
			Expect(err).ToNot(HaveOccurred())
			Expect(len).To(Equal(protocol.PacketNumberLen1))
			Expect(p).To(Equal(protocol.PacketNumber(0x42)))
		})

		It("only uses the least significant 7 bits when writing a 1 byte packet number", func() {
			b := &bytes.Buffer{}
			err := WriteVarIntPacketNumber(b, 0x1234ea, protocol.PacketNumberLen1)
			Expect(err).ToNot(HaveOccurred())
			Expect(b.Len()).To(Equal(1))
			p, len, err := ReadVarIntPacketNumber(bytes.NewReader(b.Bytes()))
			Expect(err).ToNot(HaveOccurred())
			Expect(len).To(Equal(protocol.PacketNumberLen1))
			Expect(p).To(Equal(protocol.PacketNumber(0x6a)))
		})

		It("writes a small 2 byte packet number", func() {
			b := &bytes.Buffer{}
			err := WriteVarIntPacketNumber(b, 0x42, protocol.PacketNumberLen2)
			Expect(err).ToNot(HaveOccurred())
			Expect(b.Len()).To(Equal(2))
			p, len, err := ReadVarIntPacketNumber(bytes.NewReader(b.Bytes()))
			Expect(err).ToNot(HaveOccurred())
			Expect(len).To(Equal(protocol.PacketNumberLen2))
			Expect(p).To(Equal(protocol.PacketNumber(0x42)))
		})

		It("writes a 2 byte packet number", func() {
			b := &bytes.Buffer{}
			err := WriteVarIntPacketNumber(b, 0x1337, protocol.PacketNumberLen2)
			Expect(err).ToNot(HaveOccurred())
			Expect(b.Len()).To(Equal(2))
			p, len, err := ReadVarIntPacketNumber(bytes.NewReader(b.Bytes()))
			Expect(err).ToNot(HaveOccurred())
			Expect(len).To(Equal(protocol.PacketNumberLen2))
			Expect(p).To(Equal(protocol.PacketNumber(0x1337)))
		})

		It("only uses the least significant 14 bits when writing a 2 byte packet number", func() {
			b := &bytes.Buffer{}
			err := WriteVarIntPacketNumber(b, 0x1234ff37, protocol.PacketNumberLen2)
			Expect(err).ToNot(HaveOccurred())
			Expect(b.Len()).To(Equal(2))
			p, len, err := ReadVarIntPacketNumber(bytes.NewReader(b.Bytes()))
			Expect(err).ToNot(HaveOccurred())
			Expect(len).To(Equal(protocol.PacketNumberLen2))
			Expect(p).To(Equal(protocol.PacketNumber(0x3f37)))
		})

		It("writes a small 4 byte packet number", func() {
			b := &bytes.Buffer{}
			err := WriteVarIntPacketNumber(b, 0xbeef, protocol.PacketNumberLen4)
			Expect(err).ToNot(HaveOccurred())
			Expect(b.Len()).To(Equal(4))
			p, len, err := ReadVarIntPacketNumber(bytes.NewReader(b.Bytes()))
			Expect(err).ToNot(HaveOccurred())
			Expect(len).To(Equal(protocol.PacketNumberLen4))
			Expect(p).To(Equal(protocol.PacketNumber(0xbeef)))
		})

		It("writes a 4 byte packet number", func() {
			b := &bytes.Buffer{}
			err := WriteVarIntPacketNumber(b, 0x12beef42, protocol.PacketNumberLen4)
			Expect(err).ToNot(HaveOccurred())
			Expect(b.Len()).To(Equal(4))
			p, len, err := ReadVarIntPacketNumber(bytes.NewReader(b.Bytes()))
			Expect(err).ToNot(HaveOccurred())
			Expect(len).To(Equal(protocol.PacketNumberLen4))
			Expect(p).To(Equal(protocol.PacketNumber(0x12beef42)))
		})

		It("only uses the least significant 30 bits when writing a 4 byte packet number", func() {
			b := &bytes.Buffer{}
			err := WriteVarIntPacketNumber(b, 0x1234deadbeef, protocol.PacketNumberLen4)
			Expect(err).ToNot(HaveOccurred())
			Expect(b.Len()).To(Equal(4))
			p, len, err := ReadVarIntPacketNumber(bytes.NewReader(b.Bytes()))
			Expect(err).ToNot(HaveOccurred())
			Expect(len).To(Equal(protocol.PacketNumberLen4))
			Expect(p).To(Equal(protocol.PacketNumber(0x1eadbeef)))
		})

		It("errors when encountering invalid packet number lengths", func() {
			b := &bytes.Buffer{}
			err := WriteVarIntPacketNumber(b, 0x1234deadbeef, 13)
			Expect(err).To(MatchError("invalid packet number length: 13"))
		})
	})
})
