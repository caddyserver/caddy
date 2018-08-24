package wire

import (
	"bytes"
	"io"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("ACK Frame (for gQUIC)", func() {
	Context("when parsing", func() {
		It("accepts a sample frame", func() {
			b := bytes.NewReader([]byte{0x40,
				0x1c,     // largest acked
				0x0, 0x0, // delay time
				0x1c, // block length
				0,
			})
			frame, err := parseAckFrame(b, versionBigEndian)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.LargestAcked()).To(Equal(protocol.PacketNumber(0x1c)))
			Expect(frame.LowestAcked()).To(Equal(protocol.PacketNumber(1)))
			Expect(frame.HasMissingRanges()).To(BeFalse())
			Expect(b.Len()).To(BeZero())
		})

		It("parses a frame that acks packet number 0", func() {
			b := bytes.NewReader([]byte{0x40,
				0x0,      // largest acked
				0x0, 0x0, // delay time
				0x1, // block length
				0,
			})
			frame, err := parseAckFrame(b, versionBigEndian)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.LargestAcked()).To(Equal(protocol.PacketNumber(0)))
			Expect(frame.LowestAcked()).To(Equal(protocol.PacketNumber(0)))
			Expect(frame.HasMissingRanges()).To(BeFalse())
			Expect(b.Len()).To(BeZero())
		})

		It("parses a frame with 1 ACKed packet", func() {
			b := bytes.NewReader([]byte{0x40,
				0x10,     // largest acked
				0x0, 0x0, // delay time
				0x1, // block length
				0,
			})
			frame, err := parseAckFrame(b, versionBigEndian)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.LargestAcked()).To(Equal(protocol.PacketNumber(0x10)))
			Expect(frame.LowestAcked()).To(Equal(protocol.PacketNumber(0x10)))
			Expect(frame.HasMissingRanges()).To(BeFalse())
			Expect(b.Len()).To(BeZero())
		})

		It("parses a frame that acks multiple packets, starting with 0", func() {
			b := bytes.NewReader([]byte{0x40,
				0x10,     // largest acked
				0x0, 0x0, // delay time
				0x11, // block length
				0,
			})
			frame, err := parseAckFrame(b, versionBigEndian)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.LargestAcked()).To(Equal(protocol.PacketNumber(0x10)))
			Expect(frame.LowestAcked()).To(Equal(protocol.PacketNumber(0)))
			Expect(frame.HasMissingRanges()).To(BeFalse())
			Expect(b.Len()).To(BeZero())
		})

		It("parses a frame with multiple timestamps", func() {
			b := bytes.NewReader([]byte{0x40,
				0x10,     // largest acked
				0x0, 0x0, // timestamp
				0x10,                      // block length
				0x4,                       // num timestamps
				0x1, 0x6b, 0x26, 0x4, 0x0, // 1st timestamp
				0x3, 0, 0, // 2nd timestamp
				0x2, 0, 0, // 3rd timestamp
				0x1, 0, 0, // 4th timestamp
			})
			_, err := parseAckFrame(b, versionBigEndian)
			Expect(err).ToNot(HaveOccurred())
			Expect(b.Len()).To(BeZero())
		})

		It("errors when the ACK range is too large", func() {
			// LargestAcked: 0x1c
			// Length: 0x1d => LowestAcked would be -1
			b := bytes.NewReader([]byte{0x40,
				0x1c,     // largest acked
				0x0, 0x0, // delay time
				0x1e, // block length
				0,
			})
			_, err := parseAckFrame(b, versionBigEndian)
			Expect(err).To(MatchError(errInvalidAckRanges))
		})

		It("errors when the first ACK range is empty", func() {
			b := bytes.NewReader([]byte{0x40,
				0x9,      // largest acked
				0x0, 0x0, // delay time
				0x0, // block length
				0,
			})
			_, err := parseAckFrame(b, versionBigEndian)
			Expect(err).To(MatchError("invalid first ACK range"))
		})

		It("parses the delay time", func() {
			b := bytes.NewReader([]byte{0x40,
				0x3,       // largest acked
				0x0, 0x8e, // delay time
				0x3, // block length
				0,
			})
			frame, err := parseAckFrame(b, versionBigEndian)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.LargestAcked()).To(Equal(protocol.PacketNumber(3)))
			Expect(frame.DelayTime).To(Equal(142 * time.Microsecond))
		})

		It("errors on EOFs", func() {
			data := []byte{0x60 ^ 0x4 ^ 0x1,
				0x9, 0x66, // largest acked
				0x23, 0x1, // delay time
				0x7,      // num ACk blocks
				0x0, 0x7, // 1st block
				0xff, 0x0, 0x0, // 2nd block
				0xf5, 0x2, 0x8a, // 3rd block
				0xc8, 0x0, 0xe6, // 4th block
				0xff, 0x0, 0x0, // 5th block
				0xff, 0x0, 0x0, // 6th block
				0xff, 0x0, 0x0, // 7th block
				0x23, 0x0, 0x13, // 8th blocks
				0x2,                       // num timestamps
				0x1, 0x13, 0xae, 0xb, 0x0, // 1st timestamp
				0x0, 0x80, 0x5, // 2nd timestamp
			}
			_, err := parseAckFrame(bytes.NewReader(data), versionBigEndian)
			Expect(err).NotTo(HaveOccurred())
			for i := range data {
				_, err := parseAckFrame(bytes.NewReader(data[0:i]), versionBigEndian)
				Expect(err).To(MatchError(io.EOF))
			}
		})

		Context("largest acked length", func() {
			It("parses a frame with a 2 byte packet number", func() {
				b := bytes.NewReader([]byte{0x40 | 0x4,
					0x13, 0x37, // largest acked
					0x0, 0x0, // delay time
					0x9, // block length
					0,
				})
				frame, err := parseAckFrame(b, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.LargestAcked()).To(Equal(protocol.PacketNumber(0x1337)))
				Expect(frame.LowestAcked()).To(Equal(protocol.PacketNumber(0x1337 - 0x9 + 1)))
				Expect(frame.HasMissingRanges()).To(BeFalse())
				Expect(b.Len()).To(BeZero())
			})

			It("parses a frame with a 4 byte packet number", func() {
				b := bytes.NewReader([]byte{0x40 | 0x8,
					0xde, 0xca, 0xfb, 0xad, // largest acked
					0x0, 0x0, // timesatmp
					0x5, // block length
					0,
				})
				frame, err := parseAckFrame(b, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.LargestAcked()).To(Equal(protocol.PacketNumber(0xdecafbad)))
				Expect(frame.LowestAcked()).To(Equal(protocol.PacketNumber(0xdecafbad - 5 + 1)))
				Expect(frame.HasMissingRanges()).To(BeFalse())
				Expect(b.Len()).To(BeZero())
			})

			It("parses a frame with a 6 byte packet number", func() {
				b := bytes.NewReader([]byte{0x4 | 0xc,
					0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, // largest acked
					0x0, 0x0, // delay time
					0x5, // block length
					0,
				})
				frame, err := parseAckFrame(b, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.LargestAcked()).To(Equal(protocol.PacketNumber(0xdeadbeefcafe)))
				Expect(frame.LowestAcked()).To(Equal(protocol.PacketNumber(0xdeadbeefcafe - 5 + 1)))
				Expect(frame.HasMissingRanges()).To(BeFalse())
				Expect(b.Len()).To(BeZero())
			})
		})

		Context("ACK blocks", func() {
			It("parses a frame with two ACK blocks", func() {
				b := bytes.NewReader([]byte{0x60,
					0x18,     // largest acked
					0x0, 0x0, // delay time
					0x1,       // num ACK blocks
					0x3,       // 1st block
					0x2, 0x10, // 2nd block
					0,
				})
				frame, err := parseAckFrame(b, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.LargestAcked()).To(Equal(protocol.PacketNumber(0x18)))
				Expect(frame.HasMissingRanges()).To(BeTrue())
				Expect(frame.AckRanges).To(HaveLen(2))
				Expect(frame.AckRanges[0]).To(Equal(AckRange{Smallest: 0x18 - 0x3 + 1, Largest: 0x18}))
				Expect(frame.AckRanges[1]).To(Equal(AckRange{Smallest: (0x18 - 0x3 + 1) - (0x2 + 1) - (0x10 - 1), Largest: (0x18 - 0x3 + 1) - (0x2 + 1)}))
				Expect(frame.LowestAcked()).To(Equal(protocol.PacketNumber(4)))
				Expect(b.Len()).To(BeZero())
			})

			It("rejects a frame with invalid ACK ranges", func() {
				// like the test before, but increased the last ACK range, such that the First would be negative
				b := bytes.NewReader([]byte{0x60,
					0x18,     // largest acked
					0x0, 0x0, // delay time
					0x1,       // num ACK blocks
					0x3,       // 1st block
					0x2, 0x15, // 2nd block
					0,
				})
				_, err := parseAckFrame(b, versionBigEndian)
				Expect(err).To(MatchError(errInvalidAckRanges))
			})

			It("rejects a frame that says it has ACK blocks in the typeByte, but doesn't have any", func() {
				b := bytes.NewReader([]byte{0x60 ^ 0x3,
					0x4,      // largest acked
					0x0, 0x0, // delay time
					0, // num ACK blocks
					0,
				})
				_, err := parseAckFrame(b, versionBigEndian)
				Expect(err).To(MatchError(errInvalidAckRanges))
			})

			It("parses a frame with multiple single packets missing", func() {
				b := bytes.NewReader([]byte{0x60,
					0x27,     // largest acked
					0x0, 0x0, // delay time
					0x6,      // num ACK blocks
					0x9,      // 1st block
					0x1, 0x1, // 2nd block
					0x1, 0x1, // 3rd block
					0x1, 0x1, // 4th block
					0x1, 0x1, // 5th block
					0x1, 0x1, // 6th block
					0x1, 0x13, // 7th block
					0,
				})
				frame, err := parseAckFrame(b, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.LargestAcked()).To(Equal(protocol.PacketNumber(0x27)))
				Expect(frame.HasMissingRanges()).To(BeTrue())
				Expect(frame.AckRanges).To(HaveLen(7))
				Expect(frame.AckRanges[0]).To(Equal(AckRange{Smallest: 31, Largest: 0x27}))
				Expect(frame.AckRanges[1]).To(Equal(AckRange{Smallest: 29, Largest: 29}))
				Expect(frame.AckRanges[2]).To(Equal(AckRange{Smallest: 27, Largest: 27}))
				Expect(frame.AckRanges[3]).To(Equal(AckRange{Smallest: 25, Largest: 25}))
				Expect(frame.AckRanges[4]).To(Equal(AckRange{Smallest: 23, Largest: 23}))
				Expect(frame.AckRanges[5]).To(Equal(AckRange{Smallest: 21, Largest: 21}))
				Expect(frame.AckRanges[6]).To(Equal(AckRange{Smallest: 1, Largest: 19}))
				Expect(frame.LowestAcked()).To(Equal(protocol.PacketNumber(1)))
				Expect(b.Len()).To(BeZero())
			})

			It("parses a frame with multiple longer ACK blocks", func() {
				b := bytes.NewReader([]byte{0x60,
					0x52,      // largest acked
					0xd1, 0x0, //delay time
					0x3,       // num ACK blocks
					0x17,      // 1st block
					0xa, 0x10, // 2nd block
					0x4, 0x8, // 3rd block
					0x2, 0x12, // 4th block
					0,
				})
				frame, err := parseAckFrame(b, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.LargestAcked()).To(Equal(protocol.PacketNumber(0x52)))
				Expect(frame.HasMissingRanges()).To(BeTrue())
				Expect(frame.AckRanges).To(HaveLen(4))
				Expect(frame.AckRanges[0]).To(Equal(AckRange{Smallest: 60, Largest: 0x52}))
				Expect(frame.AckRanges[1]).To(Equal(AckRange{Smallest: 34, Largest: 49}))
				Expect(frame.AckRanges[2]).To(Equal(AckRange{Smallest: 22, Largest: 29}))
				Expect(frame.AckRanges[3]).To(Equal(AckRange{Smallest: 2, Largest: 19}))
				Expect(frame.LowestAcked()).To(Equal(protocol.PacketNumber(2)))
				Expect(b.Len()).To(BeZero())
			})

			Context("more than 256 lost packets in a row", func() {
				// 255 missing packets fit into a single ACK block
				It("parses a frame with a range of 255 missing packets", func() {
					b := bytes.NewReader([]byte{0x60 ^ 0x4,
						0x1, 0x15, // largest acked
						0x0, 0x0, // delay time
						0x1,        // num ACK blocks
						0x3,        // 1st block
						0xff, 0x13, // 2nd block
						0,
					})
					frame, err := parseAckFrame(b, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked()).To(Equal(protocol.PacketNumber(0x115)))
					Expect(frame.HasMissingRanges()).To(BeTrue())
					Expect(frame.AckRanges).To(HaveLen(2))
					Expect(frame.AckRanges[0]).To(Equal(AckRange{Smallest: 20 + 255, Largest: 0x115}))
					Expect(frame.AckRanges[1]).To(Equal(AckRange{Smallest: 1, Largest: 19}))
					Expect(frame.LowestAcked()).To(Equal(protocol.PacketNumber(1)))
					Expect(b.Len()).To(BeZero())
				})

				// 256 missing packets fit into two ACK blocks
				It("parses a frame with a range of 256 missing packets", func() {
					b := bytes.NewReader([]byte{0x60 ^ 0x4,
						0x1, 0x14, // largest acked
						0x0, 0x0, // delay time
						0x2,       // num ACK blocks
						0x1,       // 1st block
						0xff, 0x0, // 2nd block
						0x1, 0x13, // 3rd block
						0,
					})
					frame, err := parseAckFrame(b, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked()).To(Equal(protocol.PacketNumber(0x114)))
					Expect(frame.HasMissingRanges()).To(BeTrue())
					Expect(frame.AckRanges).To(HaveLen(2))
					Expect(frame.AckRanges[0]).To(Equal(AckRange{Smallest: 20 + 256, Largest: 0x114}))
					Expect(frame.AckRanges[1]).To(Equal(AckRange{Smallest: 1, Largest: 19}))
					Expect(frame.LowestAcked()).To(Equal(protocol.PacketNumber(1)))
					Expect(b.Len()).To(BeZero())
				})

				It("parses a frame with an incomplete range at the end", func() {
					// this is a modified ACK frame that has 5 instead of originally 6 written ranges
					// each gap is 300 packets and thus takes 2 ranges
					// the last range is incomplete, and should be completely ignored
					b := bytes.NewReader([]byte{0x60 ^ 0x4,
						0x3, 0x9b, // largest acked
						0x0, 0x0, // delay time
						0x5,       // num ACK blocks, instead of 0x6
						0x1,       // 1st block
						0xff, 0x0, // 2nd block
						0x2d, 0x1, // 3rd block
						0xff, 0x0, // 4th block
						0x2d, 0x1, // 5th block
						0xff, 0x0, /*0x2d, 0x14,*/ // 6th block
						0,
					})
					frame, err := parseAckFrame(b, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked()).To(Equal(protocol.PacketNumber(0x39b)))
					Expect(frame.HasMissingRanges()).To(BeTrue())
					Expect(frame.AckRanges).To(HaveLen(3))
					Expect(frame.AckRanges[0]).To(Equal(AckRange{Smallest: 20 + 3*301, Largest: 20 + 3*301}))
					Expect(frame.AckRanges[1]).To(Equal(AckRange{Smallest: 20 + 2*301, Largest: 20 + 2*301}))
					Expect(frame.AckRanges[2]).To(Equal(AckRange{Smallest: 20 + 1*301, Largest: 20 + 1*301}))
					Expect(b.Len()).To(BeZero())
				})

				It("parses a frame with one long range, spanning 2 blocks, of missing packets", func() {
					// 280 missing packets
					b := bytes.NewReader([]byte{0x60 ^ 0x4,
						0x1, 0x44, // largest acked
						0x0, 0x0, // delay time
						0x2,       // num ACK blocks
						0x19,      // 1st block
						0xff, 0x0, // 2nd block
						0x19, 0x13, // 3rd block
						0,
					})
					frame, err := parseAckFrame(b, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked()).To(Equal(protocol.PacketNumber(0x144)))
					Expect(frame.HasMissingRanges()).To(BeTrue())
					Expect(frame.AckRanges).To(HaveLen(2))
					Expect(frame.AckRanges[0]).To(Equal(AckRange{Smallest: 300, Largest: 0x144}))
					Expect(frame.AckRanges[1]).To(Equal(AckRange{Smallest: 1, Largest: 19}))
					Expect(frame.LowestAcked()).To(Equal(protocol.PacketNumber(1)))
					Expect(b.Len()).To(BeZero())
				})

				It("parses a frame with one long range, spanning multiple blocks, of missing packets", func() {
					// 2345 missing packets
					b := bytes.NewReader([]byte{0x60 ^ 0x4,
						0x9, 0x5b, // largest acked
						0x0, 0x0, // delay time
						0xa,       // num ACK blocks
						0x1f,      // 1st block
						0xff, 0x0, // 2nd block
						0xff, 0x0, // 3rd block
						0xff, 0x0, // 4th block
						0xff, 0x0, // 5th block
						0xff, 0x0, // 6th block
						0xff, 0x0, // 7th block
						0xff, 0x0, // 8th block
						0xff, 0x0, // 9th block
						0xff, 0x0, // 10th block
						0x32, 0x13, // 11th block
						0,
					})
					frame, err := parseAckFrame(b, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked()).To(Equal(protocol.PacketNumber(0x95b)))
					Expect(frame.HasMissingRanges()).To(BeTrue())
					Expect(frame.AckRanges).To(HaveLen(2))
					Expect(frame.AckRanges[0]).To(Equal(AckRange{Smallest: 2365, Largest: 0x95b}))
					Expect(frame.AckRanges[1]).To(Equal(AckRange{Smallest: 1, Largest: 19}))
					Expect(frame.LowestAcked()).To(Equal(protocol.PacketNumber(1)))
					Expect(b.Len()).To(BeZero())
				})

				It("parses a frame with multiple 2 byte long ranges of missing packets", func() {
					b := bytes.NewReader([]byte{0x60 ^ 0x4 ^ 0x1,
						0x9, 0x66, // largest acked
						0x0, 0x0, // delay time
						0x7,      // num ACK blocks
						0x0, 0x7, // 1st block
						0xff, 0x0, 0x0, // 2nd block
						0xf5, 0x2, 0x8a, // 3rd block
						0xc8, 0x0, 0xe6, // 4th block
						0xff, 0x0, 0x0, // 5th block
						0xff, 0x0, 0x0, // 6th block
						0xff, 0x0, 0x0, // 7th block
						0x23, 0x0, 0x13, // 8th block
						0,
					})
					frame, err := parseAckFrame(b, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked()).To(Equal(protocol.PacketNumber(0x966)))
					Expect(frame.HasMissingRanges()).To(BeTrue())
					Expect(frame.AckRanges).To(HaveLen(4))
					Expect(frame.AckRanges[0]).To(Equal(AckRange{Smallest: 2400, Largest: 0x966}))
					Expect(frame.AckRanges[1]).To(Equal(AckRange{Smallest: 1250, Largest: 1899}))
					Expect(frame.AckRanges[2]).To(Equal(AckRange{Smallest: 820, Largest: 1049}))
					Expect(frame.AckRanges[3]).To(Equal(AckRange{Smallest: 1, Largest: 19}))
					Expect(frame.LowestAcked()).To(Equal(protocol.PacketNumber(1)))
					Expect(b.Len()).To(BeZero())
				})

				It("parses a frame with with a 4 byte ack block length", func() {
					b := bytes.NewReader([]byte{0x60 ^ 0xc ^ 0x2,
						0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, // largest acked
						0x0, 0x0, // delay time
						0x1,              // num ACK blocks
						0, 0, 0x13, 0x37, // 1st block
						0x20, 0x12, 0x34, 0x56, 0x78, // 2nd block
						0,
					})
					frame, err := parseAckFrame(b, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked()).To(Equal(protocol.PacketNumber(0xdeadbeefcafe)))
					Expect(frame.HasMissingRanges()).To(BeTrue())
					Expect(frame.AckRanges).To(HaveLen(2))
					Expect(frame.AckRanges[0]).To(Equal(AckRange{Smallest: 0xdeadbeefcafe - 0x1337 + 1, Largest: 0xdeadbeefcafe}))
					Expect(frame.AckRanges[1]).To(Equal(AckRange{Smallest: (0xdeadbeefcafe - 0x1337 + 1) - (0x20 + 1) - (0x12345678 - 1), Largest: (0xdeadbeefcafe - 0x1337 + 1) - (0x20 + 1)}))
				})

				It("parses a frame with with a 6 byte ack block length", func() {
					b := bytes.NewReader([]byte{0x60 ^ 0xc ^ 0x3,
						0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, // largest acked
						0x0, 0x0, // delay time
						0x1,                    // num ACk blocks
						0, 0, 0, 0, 0x13, 0x37, // 1st block
						0x20, 0x0, 0xab, 0x12, 0x34, 0x56, 0x78, // 2nd block
						0,
					})
					frame, err := parseAckFrame(b, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked()).To(Equal(protocol.PacketNumber(0xdeadbeefcafe)))
					Expect(frame.HasMissingRanges()).To(BeTrue())
					Expect(frame.AckRanges).To(HaveLen(2))
					Expect(frame.AckRanges[0]).To(Equal(AckRange{Smallest: 0xdeadbeefcafe - 0x1337 + 1, Largest: 0xdeadbeefcafe}))
					Expect(frame.AckRanges[1]).To(Equal(AckRange{Smallest: (0xdeadbeefcafe - 0x1337 + 1) - (0x20 + 1) - (0xab12345678 - 1), Largest: (0xdeadbeefcafe - 0x1337 + 1) - (0x20 + 1)}))
				})
			})
		})
	})

	Context("when writing", func() {
		var b *bytes.Buffer

		BeforeEach(func() {
			b = &bytes.Buffer{}
		})

		Context("self-consistency", func() {
			It("writes a simple ACK frame", func() {
				frameOrig := &AckFrame{
					AckRanges: []AckRange{{Smallest: 1, Largest: 1}},
					DelayTime: 876 * time.Microsecond,
				}
				err := frameOrig.Write(b, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				r := bytes.NewReader(b.Bytes())
				frame, err := parseAckFrame(r, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.LargestAcked()).To(Equal(frameOrig.LargestAcked()))
				Expect(frame.HasMissingRanges()).To(BeFalse())
				Expect(frame.DelayTime).To(Equal(frameOrig.DelayTime))
				Expect(r.Len()).To(BeZero())
			})

			It("writes an ACK that also acks packet 0", func() {
				frameOrig := &AckFrame{
					AckRanges: []AckRange{{Smallest: 0, Largest: 1}},
				}
				err := frameOrig.Write(b, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				r := bytes.NewReader(b.Bytes())
				frame, err := parseAckFrame(r, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.LargestAcked()).To(Equal(frameOrig.LargestAcked()))
				Expect(frame.HasMissingRanges()).To(BeFalse())
				Expect(r.Len()).To(BeZero())
			})

			It("writes the correct block length in a simple ACK frame", func() {
				frameOrig := &AckFrame{
					AckRanges: []AckRange{{Smallest: 10, Largest: 20}},
				}
				err := frameOrig.Write(b, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				r := bytes.NewReader(b.Bytes())
				frame, err := parseAckFrame(r, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.LargestAcked()).To(Equal(frameOrig.LargestAcked()))
				Expect(frame.LowestAcked()).To(Equal(frameOrig.LowestAcked()))
				Expect(frame.HasMissingRanges()).To(BeFalse())
				Expect(r.Len()).To(BeZero())
			})

			It("writes a simple ACK frame with a high packet number", func() {
				frameOrig := &AckFrame{
					AckRanges: []AckRange{{Smallest: 0xdeadbeefcafe, Largest: 0xdeadbeefcafe}},
				}
				err := frameOrig.Write(b, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				r := bytes.NewReader(b.Bytes())
				frame, err := parseAckFrame(r, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.LargestAcked()).To(Equal(frameOrig.LargestAcked()))
				Expect(frame.HasMissingRanges()).To(BeFalse())
				Expect(r.Len()).To(BeZero())
			})

			It("writes an ACK frame with one packet missing", func() {
				frameOrig := &AckFrame{
					AckRanges: []AckRange{
						{Smallest: 25, Largest: 40},
						{Smallest: 0, Largest: 23},
					},
				}
				err := frameOrig.Write(b, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				r := bytes.NewReader(b.Bytes())
				frame, err := parseAckFrame(r, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.LargestAcked()).To(Equal(frameOrig.LargestAcked()))
				Expect(frame.LowestAcked()).To(Equal(frameOrig.LowestAcked()))
				Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
				Expect(r.Len()).To(BeZero())
			})

			It("writes an ACK frame with multiple missing packets", func() {
				frameOrig := &AckFrame{
					AckRanges: []AckRange{
						{Smallest: 22, Largest: 25},
						{Smallest: 15, Largest: 18},
						{Smallest: 13, Largest: 13},
						{Smallest: 1, Largest: 10},
					},
				}
				err := frameOrig.Write(b, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				r := bytes.NewReader(b.Bytes())
				frame, err := parseAckFrame(r, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.LargestAcked()).To(Equal(frameOrig.LargestAcked()))
				Expect(frame.LowestAcked()).To(Equal(frameOrig.LowestAcked()))
				Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
				Expect(r.Len()).To(BeZero())
			})

			Context("longer gaps between ACK blocks", func() {
				It("only writes one block for 254 lost packets", func() {
					frameOrig := &AckFrame{
						AckRanges: []AckRange{
							{Smallest: 20 + 254, Largest: 300},
							{Smallest: 1, Largest: 19},
						},
					}
					Expect(frameOrig.numWritableNackRanges()).To(Equal(uint64(2)))
					err := frameOrig.Write(b, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					r := bytes.NewReader(b.Bytes())
					frame, err := parseAckFrame(r, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked()).To(Equal(frameOrig.LargestAcked()))
					Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
				})

				It("only writes one block for 255 lost packets", func() {
					frameOrig := &AckFrame{
						AckRanges: []AckRange{
							{Smallest: 20 + 255, Largest: 300},
							{Smallest: 1, Largest: 19},
						},
					}
					Expect(frameOrig.numWritableNackRanges()).To(Equal(uint64(2)))
					err := frameOrig.Write(b, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					r := bytes.NewReader(b.Bytes())
					frame, err := parseAckFrame(r, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked()).To(Equal(frameOrig.LargestAcked()))
					Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
				})

				It("writes two blocks for 256 lost packets", func() {
					frameOrig := &AckFrame{
						AckRanges: []AckRange{
							{Smallest: 20 + 256, Largest: 300},
							{Smallest: 1, Largest: 19},
						},
					}
					Expect(frameOrig.numWritableNackRanges()).To(Equal(uint64(3)))
					err := frameOrig.Write(b, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					r := bytes.NewReader(b.Bytes())
					frame, err := parseAckFrame(r, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked()).To(Equal(frameOrig.LargestAcked()))
					Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
				})

				It("writes two blocks for 510 lost packets", func() {
					frameOrig := &AckFrame{
						AckRanges: []AckRange{
							{Smallest: 20 + 510, Largest: 600},
							{Smallest: 1, Largest: 19},
						},
					}
					Expect(frameOrig.numWritableNackRanges()).To(Equal(uint64(3)))
					err := frameOrig.Write(b, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					r := bytes.NewReader(b.Bytes())
					frame, err := parseAckFrame(r, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked()).To(Equal(frameOrig.LargestAcked()))
					Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
				})

				It("writes three blocks for 511 lost packets", func() {
					frameOrig := &AckFrame{
						AckRanges: []AckRange{
							{Smallest: 20 + 511, Largest: 600},
							{Smallest: 1, Largest: 19},
						},
					}
					Expect(frameOrig.numWritableNackRanges()).To(Equal(uint64(4)))
					err := frameOrig.Write(b, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					r := bytes.NewReader(b.Bytes())
					frame, err := parseAckFrame(r, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked()).To(Equal(frameOrig.LargestAcked()))
					Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
				})

				It("writes three blocks for 512 lost packets", func() {
					frameOrig := &AckFrame{
						AckRanges: []AckRange{
							{Smallest: 20 + 512, Largest: 600},
							{Smallest: 1, Largest: 19},
						},
					}
					Expect(frameOrig.numWritableNackRanges()).To(Equal(uint64(4)))
					err := frameOrig.Write(b, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					r := bytes.NewReader(b.Bytes())
					frame, err := parseAckFrame(r, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked()).To(Equal(frameOrig.LargestAcked()))
					Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
				})

				It("writes multiple blocks for a lot of lost packets", func() {
					frameOrig := &AckFrame{
						AckRanges: []AckRange{
							{Smallest: 2900, Largest: 3000},
							{Smallest: 1, Largest: 19},
						},
					}
					err := frameOrig.Write(b, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					r := bytes.NewReader(b.Bytes())
					frame, err := parseAckFrame(r, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked()).To(Equal(frameOrig.LargestAcked()))
					Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
				})

				It("writes multiple longer blocks for 256 lost packets", func() {
					frameOrig := &AckFrame{
						AckRanges: []AckRange{
							{Smallest: 2900, Largest: 3600},
							{Smallest: 1000, Largest: 2500},
							{Smallest: 1, Largest: 19},
						},
					}
					err := frameOrig.Write(b, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					r := bytes.NewReader(b.Bytes())
					frame, err := parseAckFrame(r, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked()).To(Equal(frameOrig.LargestAcked()))
					Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
				})
			})

			Context("largest acked length", func() {
				It("writes a 1 largest acked", func() {
					frameOrig := &AckFrame{
						AckRanges: []AckRange{{Smallest: 1, Largest: 200}},
					}
					err := frameOrig.Write(b, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(b.Bytes()[0] & 0x3).To(Equal(byte(0x0)))
					r := bytes.NewReader(b.Bytes())
					frame, err := parseAckFrame(r, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked()).To(Equal(frameOrig.LargestAcked()))
					Expect(frame.LowestAcked()).To(Equal(frameOrig.LowestAcked()))
					Expect(r.Len()).To(BeZero())
				})

				It("writes a 2 byte largest acked", func() {
					frameOrig := &AckFrame{
						AckRanges: []AckRange{{Smallest: 1, Largest: 0x100}},
					}
					err := frameOrig.Write(b, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(b.Bytes()[0] & 0x3).To(Equal(byte(0x1)))
					r := bytes.NewReader(b.Bytes())
					frame, err := parseAckFrame(r, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked()).To(Equal(frameOrig.LargestAcked()))
					Expect(frame.LowestAcked()).To(Equal(frameOrig.LowestAcked()))
					Expect(r.Len()).To(BeZero())
				})

				It("writes a 4 byte largest acked", func() {
					frameOrig := &AckFrame{
						AckRanges: []AckRange{{Smallest: 1, Largest: 0x10000}},
					}
					err := frameOrig.Write(b, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(b.Bytes()[0] & 0x3).To(Equal(byte(0x2)))
					r := bytes.NewReader(b.Bytes())
					frame, err := parseAckFrame(r, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked()).To(Equal(frameOrig.LargestAcked()))
					Expect(frame.LowestAcked()).To(Equal(frameOrig.LowestAcked()))
					Expect(r.Len()).To(BeZero())
				})

				It("writes a 6 byte largest acked", func() {
					frameOrig := &AckFrame{
						AckRanges: []AckRange{{Smallest: 1, Largest: 0x100000000}},
					}
					err := frameOrig.Write(b, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(b.Bytes()[0] & 0x3).To(Equal(byte(0x3)))
					r := bytes.NewReader(b.Bytes())
					frame, err := parseAckFrame(r, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked()).To(Equal(frameOrig.LargestAcked()))
					Expect(frame.LowestAcked()).To(Equal(frameOrig.LowestAcked()))
					Expect(r.Len()).To(BeZero())
				})
			})

			Context("ack block length", func() {
				It("writes a 1 byte ack block length, if all ACK blocks are short", func() {
					frameOrig := &AckFrame{
						AckRanges: []AckRange{
							{Smallest: 5000, Largest: 5001},
							{Smallest: 250, Largest: 300},
							{Smallest: 1, Largest: 200},
						},
					}
					err := frameOrig.Write(b, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(b.Bytes()[0] & 0x3).To(Equal(byte(0x0)))
					r := bytes.NewReader(b.Bytes())
					frame, err := parseAckFrame(r, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked()).To(Equal(frameOrig.LargestAcked()))
					Expect(frame.LowestAcked()).To(Equal(frameOrig.LowestAcked()))
					Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
					Expect(r.Len()).To(BeZero())
				})

				It("writes a 2 byte ack block length, for a frame with one ACK block", func() {
					frameOrig := &AckFrame{
						AckRanges: []AckRange{
							{Smallest: 9990, Largest: 10000},
							{Smallest: 1, Largest: 9988},
						},
					}
					err := frameOrig.Write(b, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(b.Bytes()[0] & 0x3).To(Equal(byte(0x1)))
					r := bytes.NewReader(b.Bytes())
					frame, err := parseAckFrame(r, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked()).To(Equal(frameOrig.LargestAcked()))
					Expect(frame.LowestAcked()).To(Equal(frameOrig.LowestAcked()))
					Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
					Expect(r.Len()).To(BeZero())
				})

				It("writes a 2 byte ack block length, for a frame with multiple ACK blocks", func() {
					frameOrig := &AckFrame{
						AckRanges: []AckRange{
							{Smallest: 9990, Largest: 10000},
							{Smallest: 1, Largest: 256},
						},
					}
					err := frameOrig.Write(b, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(b.Bytes()[0] & 0x3).To(Equal(byte(0x1)))
					r := bytes.NewReader(b.Bytes())
					frame, err := parseAckFrame(r, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked()).To(Equal(frameOrig.LargestAcked()))
					Expect(frame.LowestAcked()).To(Equal(frameOrig.LowestAcked()))
					Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
					Expect(r.Len()).To(BeZero())
				})

				It("writes a 4 byte ack block length, for a frame with single ACK blocks", func() {
					frameOrig := &AckFrame{
						AckRanges: []AckRange{
							{Smallest: 9990, Largest: 0xdeadbeef},
							{Smallest: 1, Largest: 9988},
						},
					}
					err := frameOrig.Write(b, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(b.Bytes()[0] & 0x3).To(Equal(byte(0x2)))
					r := bytes.NewReader(b.Bytes())
					frame, err := parseAckFrame(r, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked()).To(Equal(frameOrig.LargestAcked()))
					Expect(frame.LowestAcked()).To(Equal(frameOrig.LowestAcked()))
					Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
					Expect(r.Len()).To(BeZero())
				})

				It("writes a 4 byte ack block length, for a frame with multiple ACK blocks", func() {
					frameOrig := &AckFrame{
						AckRanges: []AckRange{
							{Smallest: 9990, Largest: 0xdeadbeef},
							{Smallest: 1, Largest: 256},
						},
					}
					err := frameOrig.Write(b, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(b.Bytes()[0] & 0x3).To(Equal(byte(0x2)))
					r := bytes.NewReader(b.Bytes())
					frame, err := parseAckFrame(r, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked()).To(Equal(frameOrig.LargestAcked()))
					Expect(frame.LowestAcked()).To(Equal(frameOrig.LowestAcked()))
					Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
					Expect(r.Len()).To(BeZero())
				})

				It("writes a 6 byte ack block length, for a frame with a single ACK blocks", func() {
					frameOrig := &AckFrame{
						AckRanges: []AckRange{
							{Smallest: 9990, Largest: 0xdeadbeefcafe},
							{Smallest: 1, Largest: 9988},
						},
					}
					err := frameOrig.Write(b, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(b.Bytes()[0] & 0x3).To(Equal(byte(0x3)))
					r := bytes.NewReader(b.Bytes())
					frame, err := parseAckFrame(r, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked()).To(Equal(frameOrig.LargestAcked()))
					Expect(frame.LowestAcked()).To(Equal(frameOrig.LowestAcked()))
					Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
					Expect(r.Len()).To(BeZero())
				})

				It("writes a 6 byte ack block length, for a frame with multiple ACK blocks", func() {
					frameOrig := &AckFrame{
						AckRanges: []AckRange{
							{Smallest: 9990, Largest: 0xdeadbeefcafe},
							{Smallest: 1, Largest: 256},
						},
					}
					err := frameOrig.Write(b, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(b.Bytes()[0] & 0x3).To(Equal(byte(0x3)))
					r := bytes.NewReader(b.Bytes())
					frame, err := parseAckFrame(r, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked()).To(Equal(frameOrig.LargestAcked()))
					Expect(frame.LowestAcked()).To(Equal(frameOrig.LowestAcked()))
					Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
					Expect(r.Len()).To(BeZero())
				})
			})

			Context("too many ACK blocks", func() {
				It("skips the lowest ACK ranges, if there are more than 255 AckRanges", func() {
					ackRanges := make([]AckRange, 300)
					for i := 1; i <= 300; i++ {
						ackRanges[300-i] = AckRange{Smallest: protocol.PacketNumber(3 * i), Largest: protocol.PacketNumber(3*i + 1)}
					}
					frameOrig := &AckFrame{AckRanges: ackRanges}
					err := frameOrig.Write(b, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					r := bytes.NewReader(b.Bytes())
					frame, err := parseAckFrame(r, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked()).To(Equal(frameOrig.LargestAcked()))
					Expect(frame.LowestAcked()).To(Equal(ackRanges[254].Smallest))
					Expect(frame.AckRanges).To(HaveLen(0xFF))
					Expect(frame.validateAckRanges()).To(BeTrue())
				})

				It("skips the lowest ACK ranges, if the gaps are large", func() {
					ackRanges := make([]AckRange, 100)
					// every AckRange will take 4 written ACK ranges
					for i := 1; i <= 100; i++ {
						ackRanges[100-i] = AckRange{Smallest: protocol.PacketNumber(1000 * i), Largest: protocol.PacketNumber(1000*i + 1)}
					}
					frameOrig := &AckFrame{AckRanges: ackRanges}
					err := frameOrig.Write(b, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					r := bytes.NewReader(b.Bytes())
					frame, err := parseAckFrame(r, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked()).To(Equal(frameOrig.LargestAcked()))
					Expect(frame.LowestAcked()).To(Equal(ackRanges[255/4].Smallest))
					Expect(frame.validateAckRanges()).To(BeTrue())
				})

				It("works with huge gaps", func() {
					ackRanges := []AckRange{
						{Smallest: 2 * 255 * 200, Largest: 2*255*200 + 1},
						{Smallest: 1 * 255 * 200, Largest: 1*255*200 + 1},
						{Smallest: 1, Largest: 2},
					}
					frameOrig := &AckFrame{AckRanges: ackRanges}
					err := frameOrig.Write(b, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					r := bytes.NewReader(b.Bytes())
					frame, err := parseAckFrame(r, versionBigEndian)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.LargestAcked()).To(Equal(frameOrig.LargestAcked()))
					Expect(frame.AckRanges).To(HaveLen(2))
					Expect(frame.LowestAcked()).To(Equal(ackRanges[1].Smallest))
					Expect(frame.validateAckRanges()).To(BeTrue())
				})
			})
		})

		Context("min length", func() {
			It("has proper min length", func() {
				f := &AckFrame{
					AckRanges: []AckRange{{Smallest: 1, Largest: 1}},
				}
				err := f.Write(b, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(f.Length(versionBigEndian)).To(Equal(protocol.ByteCount(b.Len())))
			})

			It("has proper min length with a large LargestObserved", func() {
				f := &AckFrame{
					AckRanges: []AckRange{{Smallest: 1, Largest: 0xdeadbeefcafe}},
				}
				err := f.Write(b, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(f.Length(versionBigEndian)).To(Equal(protocol.ByteCount(b.Len())))
			})

			It("has the proper min length for an ACK with missing packets", func() {
				f := &AckFrame{
					AckRanges: []AckRange{
						{Smallest: 1000, Largest: 2000},
						{Smallest: 50, Largest: 900},
						{Smallest: 10, Largest: 23},
					},
				}
				err := f.Write(b, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(f.Length(versionBigEndian)).To(Equal(protocol.ByteCount(b.Len())))
			})

			It("has the proper min length for an ACK with long gaps of missing packets", func() {
				f := &AckFrame{
					AckRanges: []AckRange{
						{Smallest: 1500, Largest: 2000},
						{Smallest: 290, Largest: 295},
						{Smallest: 1, Largest: 19},
					},
				}
				err := f.Write(b, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(f.Length(versionBigEndian)).To(Equal(protocol.ByteCount(b.Len())))
			})

			It("has the proper min length for an ACK with a long ACK range", func() {
				largestAcked := protocol.PacketNumber(2 + 0xFFFFFF)
				f := &AckFrame{
					AckRanges: []AckRange{
						{Smallest: 1500, Largest: largestAcked},
						{Smallest: 290, Largest: 295},
						{Smallest: 1, Largest: 19},
					},
				}
				err := f.Write(b, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(f.Length(versionBigEndian)).To(Equal(protocol.ByteCount(b.Len())))
			})
		})
	})
})
