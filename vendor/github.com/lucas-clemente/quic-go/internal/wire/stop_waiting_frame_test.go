package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("StopWaitingFrame", func() {
	Context("when parsing", func() {
		Context("in big endian", func() {
			It("accepts sample frame", func() {
				b := bytes.NewReader([]byte{0x06, 0x12, 0x34})
				frame, err := parseStopWaitingFrame(b, 0x1337, 2, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.LeastUnacked).To(Equal(protocol.PacketNumber(0x1337 - 0x1234)))
				Expect(b.Len()).To(BeZero())
			})
		})

		It("rejects frames that would have a negative LeastUnacked value", func() {
			b := bytes.NewReader([]byte{0x06, 0xD})
			_, err := parseStopWaitingFrame(b, 10, 1, protocol.VersionWhatever)
			Expect(err).To(HaveOccurred())
			Expect(b.Len()).To(BeZero())
		})

		It("parses a frame with 0 as LeastUnacked", func() {
			b := bytes.NewReader([]byte{0x6, 0x8})
			frame, err := parseStopWaitingFrame(b, 8, 1, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.LeastUnacked).To(Equal(protocol.PacketNumber(0)))
			Expect(b.Len()).To(BeZero())
		})

		It("rejects frames that underflow LeastUnacked", func() {
			b := bytes.NewReader([]byte{0x6, 0x9})
			_, err := parseStopWaitingFrame(b, 8, 1, protocol.VersionWhatever)
			Expect(err).To(MatchError("invalid LeastUnackedDelta"))
		})

		It("errors on EOFs", func() {
			data := []byte{0x06, 0x03}
			_, err := parseStopWaitingFrame(bytes.NewReader(data), 5, 1, protocol.VersionWhatever)
			Expect(err).NotTo(HaveOccurred())
			for i := range data {
				_, err := parseStopWaitingFrame(bytes.NewReader(data[0:i]), 5, 1, protocol.VersionWhatever)
				Expect(err).To(HaveOccurred())
			}
		})
	})

	Context("when writing", func() {
		It("writes a sample frame", func() {
			b := &bytes.Buffer{}
			frame := &StopWaitingFrame{
				LeastUnacked:    10,
				PacketNumber:    13,
				PacketNumberLen: protocol.PacketNumberLen6,
			}
			err := frame.Write(b, versionBigEndian)
			Expect(err).ToNot(HaveOccurred())
			Expect(b.Bytes()[0]).To(Equal(uint8(0x06)))
			Expect(b.Bytes()[1:7]).To(Equal([]byte{0, 0, 0, 0, 0, 3}))
		})

		It("writes a frame for LeastUnacked = 0", func() {
			b := &bytes.Buffer{}
			frame := &StopWaitingFrame{
				LeastUnacked:    0,
				PacketNumber:    8,
				PacketNumberLen: protocol.PacketNumberLen1,
			}
			err := frame.Write(b, versionBigEndian)
			Expect(err).ToNot(HaveOccurred())
			Expect(b.Bytes()).To(Equal([]byte{0x6, 0x8}))
		})

		It("errors when PacketNumber was not set", func() {
			b := &bytes.Buffer{}
			frame := &StopWaitingFrame{
				LeastUnacked:    10,
				PacketNumberLen: protocol.PacketNumberLen1,
			}
			err := frame.Write(b, versionBigEndian)
			Expect(err).To(MatchError(errPacketNumberNotSet))
		})

		It("errors when PacketNumberLen was not set", func() {
			b := &bytes.Buffer{}
			frame := &StopWaitingFrame{
				LeastUnacked: 10,
				PacketNumber: 13,
			}
			err := frame.Write(b, versionBigEndian)
			Expect(err).To(MatchError(errPacketNumberLenNotSet))
		})

		It("errors when the LeastUnackedDelta would be negative", func() {
			b := &bytes.Buffer{}
			frame := &StopWaitingFrame{
				LeastUnacked:    10,
				PacketNumber:    5,
				PacketNumberLen: protocol.PacketNumberLen1,
			}
			err := frame.Write(b, versionBigEndian)
			Expect(err).To(MatchError(errLeastUnackedHigherThanPacketNumber))
		})

		It("refuses to write for IETF QUIC", func() {
			b := &bytes.Buffer{}
			frame := &StopWaitingFrame{
				LeastUnacked:    10,
				PacketNumber:    13,
				PacketNumberLen: protocol.PacketNumberLen6,
			}
			err := frame.Write(b, versionIETFFrames)
			Expect(err).To(MatchError("STOP_WAITING not defined in IETF QUIC"))
		})

		Context("LeastUnackedDelta length", func() {
			Context("in big endian", func() {
				It("writes a 1-byte LeastUnackedDelta", func() {
					b := &bytes.Buffer{}
					frame := &StopWaitingFrame{
						LeastUnacked:    10,
						PacketNumber:    13,
						PacketNumberLen: protocol.PacketNumberLen1,
					}
					err := frame.Write(b, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(b.Len()).To(Equal(2))
					Expect(b.Bytes()[1]).To(Equal(uint8(3)))
				})

				It("writes a 2-byte LeastUnackedDelta", func() {
					b := &bytes.Buffer{}
					frame := &StopWaitingFrame{
						LeastUnacked:    0x10,
						PacketNumber:    0x1300,
						PacketNumberLen: protocol.PacketNumberLen2,
					}
					err := frame.Write(b, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(b.Len()).To(Equal(3))
					Expect(b.Bytes()[1:3]).To(Equal([]byte{0x12, 0xf0}))
				})

				It("writes a 4-byte LeastUnackedDelta", func() {
					b := &bytes.Buffer{}
					frame := &StopWaitingFrame{
						LeastUnacked:    0x1000,
						PacketNumber:    0x12345678,
						PacketNumberLen: protocol.PacketNumberLen4,
					}
					err := frame.Write(b, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(b.Len()).To(Equal(5))
					Expect(b.Bytes()[1:5]).To(Equal([]byte{0x12, 0x34, 0x46, 0x78}))
				})

				It("writes a 6-byte LeastUnackedDelta, for a delta that fits into 6 bytes", func() {
					b := &bytes.Buffer{}
					frame := &StopWaitingFrame{
						LeastUnacked:    0x10,
						PacketNumber:    0x123456789abc,
						PacketNumberLen: protocol.PacketNumberLen6,
					}
					err := frame.Write(b, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(b.Len()).To(Equal(7))
					Expect(b.Bytes()[1:7]).To(Equal([]byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc - 0x10}))
				})
			})
		})
	})

	Context("Length", func() {
		It("calculates the right length", func() {
			for _, length := range []protocol.PacketNumberLen{protocol.PacketNumberLen1, protocol.PacketNumberLen2, protocol.PacketNumberLen4, protocol.PacketNumberLen6} {
				frame := &StopWaitingFrame{
					LeastUnacked:    10,
					PacketNumberLen: length,
				}
				Expect(frame.Length(protocol.VersionWhatever)).To(Equal(protocol.ByteCount(length + 1)))
			}
		})
	})

	Context("self consistency", func() {
		It("reads a STOP_WAITING frame that it wrote", func() {
			packetNumber := protocol.PacketNumber(13)
			frame := &StopWaitingFrame{
				LeastUnacked:    10,
				PacketNumber:    packetNumber,
				PacketNumberLen: protocol.PacketNumberLen4,
			}
			b := &bytes.Buffer{}
			err := frame.Write(b, versionBigEndian)
			Expect(err).ToNot(HaveOccurred())
			readframe, err := parseStopWaitingFrame(bytes.NewReader(b.Bytes()), packetNumber, protocol.PacketNumberLen4, versionBigEndian)
			Expect(err).ToNot(HaveOccurred())
			Expect(readframe.LeastUnacked).To(Equal(frame.LeastUnacked))
		})
	})
})
