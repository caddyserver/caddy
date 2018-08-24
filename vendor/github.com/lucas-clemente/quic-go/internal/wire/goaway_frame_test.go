package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/qerr"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("GoawayFrame", func() {
	Context("when parsing", func() {
		Context("in big endian", func() {
			It("accepts sample frame", func() {
				b := bytes.NewReader([]byte{0x3,
					0x0, 0x0, 0x13, 0x37, // error code
					0x0, 0x0, 0x12, 0x34, // last good stream id
					0x0, 0x3, // reason phrase length
					'f', 'o', 'o',
				})
				frame, err := parseGoawayFrame(b, versionBigEndian)
				Expect(frame).To(Equal(&GoawayFrame{
					ErrorCode:      0x1337,
					LastGoodStream: 0x1234,
					ReasonPhrase:   "foo",
				}))
				Expect(err).ToNot(HaveOccurred())
				Expect(b.Len()).To(BeZero())
			})

			It("errors on EOFs", func() {
				data := []byte{0x3,
					0x0, 0x0, 0x0, 0x1, // error code
					0x0, 0x0, 0x0, 0x2, // last good stream id
					0x0, 0x3, // reason phrase length
					'f', 'o', 'o',
				}
				_, err := parseGoawayFrame(bytes.NewReader(data), versionBigEndian)
				Expect(err).NotTo(HaveOccurred())
				for i := range data {
					_, err := parseGoawayFrame(bytes.NewReader(data[0:i]), versionBigEndian)
					Expect(err).To(HaveOccurred())
				}
			})
		})

		It("rejects long reason phrases", func() {
			b := bytes.NewReader([]byte{0x3,
				0x1, 0x0, 0x0, 0x0, // error code
				0x2, 0x0, 0x0, 0x0, // last good stream id
				0xff, 0xff, // reason phrase length
			})
			_, err := parseGoawayFrame(b, protocol.VersionWhatever)
			Expect(err).To(MatchError(qerr.Error(qerr.InvalidGoawayData, "reason phrase too long")))
		})
	})

	Context("when writing", func() {
		Context("in big endian", func() {
			It("writes a sample frame", func() {
				b := &bytes.Buffer{}
				frame := GoawayFrame{
					ErrorCode:      0x1337,
					LastGoodStream: 2,
					ReasonPhrase:   "foo",
				}
				err := frame.Write(b, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(b.Bytes()).To(Equal([]byte{0x3,
					0x0, 0x0, 0x13, 0x37, // reason code
					0x0, 0x0, 0x0, 0x2, // last good stream id
					0x0, 0x3, // reason phrase length
					'f', 'o', 'o',
				}))
			})
		})

		It("has the correct min length", func() {
			frame := GoawayFrame{
				ReasonPhrase: "foo",
			}
			Expect(frame.Length(0)).To(Equal(protocol.ByteCount(14)))
		})
	})
})
