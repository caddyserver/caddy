package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("RST_STREAM frame", func() {
	Context("when parsing", func() {
		Context("in varint encoding", func() {
			It("accepts sample frame", func() {
				data := []byte{0x1}
				data = append(data, encodeVarInt(0xdeadbeef)...)  // stream ID
				data = append(data, []byte{0x13, 0x37}...)        // error code
				data = append(data, encodeVarInt(0x987654321)...) // byte offset
				b := bytes.NewReader(data)
				frame, err := parseRstStreamFrame(b, versionIETFFrames)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.StreamID).To(Equal(protocol.StreamID(0xdeadbeef)))
				Expect(frame.ByteOffset).To(Equal(protocol.ByteCount(0x987654321)))
				Expect(frame.ErrorCode).To(Equal(protocol.ApplicationErrorCode(0x1337)))
			})

			It("errors on EOFs", func() {
				data := []byte{0x1}
				data = append(data, encodeVarInt(0xdeadbeef)...)  // stream ID
				data = append(data, []byte{0x13, 0x37}...)        // error code
				data = append(data, encodeVarInt(0x987654321)...) // byte offset
				_, err := parseRstStreamFrame(bytes.NewReader(data), versionIETFFrames)
				Expect(err).NotTo(HaveOccurred())
				for i := range data {
					_, err := parseRstStreamFrame(bytes.NewReader(data[0:i]), versionIETFFrames)
					Expect(err).To(HaveOccurred())
				}
			})
		})

		Context("in big endian", func() {
			It("accepts sample frame", func() {
				b := bytes.NewReader([]byte{0x1,
					0xde, 0xad, 0xbe, 0xef, // stream id
					0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // byte offset
					0x0, 0x0, 0xca, 0xfe, // error code
				})
				frame, err := parseRstStreamFrame(b, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.StreamID).To(Equal(protocol.StreamID(0xdeadbeef)))
				Expect(frame.ByteOffset).To(Equal(protocol.ByteCount(0x8877665544332211)))
				Expect(frame.ErrorCode).To(Equal(protocol.ApplicationErrorCode(0xcafe)))
			})

			It("errors on EOFs", func() {
				data := []byte{0x1,
					0xef, 0xbe, 0xad, 0xde, 0x44, // stream id
					0x33, 0x22, 0x11, 0xad, 0xfb, 0xca, 0xde, 0x34, // byte offset
					0x12, 0x37, 0x13, // error code
				}
				_, err := parseRstStreamFrame(bytes.NewReader(data), versionBigEndian)
				Expect(err).NotTo(HaveOccurred())
				for i := range data {
					_, err := parseRstStreamFrame(bytes.NewReader(data[0:i]), versionBigEndian)
					Expect(err).To(HaveOccurred())
				}
			})
		})
	})

	Context("when writing", func() {
		Context("in varint encoding", func() {
			It("writes a sample frame", func() {
				frame := RstStreamFrame{
					StreamID:   0x1337,
					ByteOffset: 0x11223344decafbad,
					ErrorCode:  0xcafe,
				}
				b := &bytes.Buffer{}
				err := frame.Write(b, versionIETFFrames)
				Expect(err).ToNot(HaveOccurred())
				expected := []byte{0x1}
				expected = append(expected, encodeVarInt(0x1337)...)
				expected = append(expected, []byte{0xca, 0xfe}...)
				expected = append(expected, encodeVarInt(0x11223344decafbad)...)
				Expect(b.Bytes()).To(Equal(expected))
			})

			It("has the correct min length", func() {
				rst := RstStreamFrame{
					StreamID:   0x1337,
					ByteOffset: 0x1234567,
					ErrorCode:  0xde,
				}
				expectedLen := 1 + utils.VarIntLen(0x1337) + utils.VarIntLen(0x1234567) + 2
				Expect(rst.Length(versionIETFFrames)).To(Equal(expectedLen))
			})
		})

		Context("in big endian", func() {
			It("writes a sample frame", func() {
				frame := RstStreamFrame{
					StreamID:   0x1337,
					ByteOffset: 0x11223344decafbad,
					ErrorCode:  0xcafe,
				}
				b := &bytes.Buffer{}
				err := frame.Write(b, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(b.Bytes()).To(Equal([]byte{0x01,
					0x0, 0x0, 0x13, 0x37, // stream id
					0x11, 0x22, 0x33, 0x44, 0xde, 0xca, 0xfb, 0xad, // byte offset
					0x0, 0x0, 0xca, 0xfe, // error code
				}))
			})

			It("has the correct min length", func() {
				rst := RstStreamFrame{
					StreamID:   0x1337,
					ByteOffset: 0x1000,
					ErrorCode:  0xde,
				}
				Expect(rst.Length(versionBigEndian)).To(Equal(protocol.ByteCount(17)))
			})
		})
	})
})
