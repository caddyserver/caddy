package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("WINDOW_UPDATE frame", func() {
	Context("parsing", func() {
		Context("in big endian", func() {
			It("parses a stream-level WINDOW_UPDATE", func() {
				b := bytes.NewReader([]byte{0x4,
					0xde, 0xad, 0xbe, 0xef, // stream id
					0xde, 0xca, 0xfb, 0xad, 0x11, 0x22, 0x33, 0x44, // byte offset
				})
				f, err := parseWindowUpdateFrame(b, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(f).To(BeAssignableToTypeOf(&MaxStreamDataFrame{}))
				frame := f.(*MaxStreamDataFrame)
				Expect(frame.ByteOffset).To(Equal(protocol.ByteCount(0xdecafbad11223344)))
				Expect(frame.StreamID).To(Equal(protocol.StreamID(0xdeadbeef)))
			})

			It("parses a connection-level WINDOW_UPDATE", func() {
				b := bytes.NewReader([]byte{0x4,
					0x0, 0x0, 0x0, 0x0, // stream id
					0xde, 0xca, 0xfb, 0xad, 0x11, 0x22, 0x33, 0x44, // byte offset
				})
				f, err := parseWindowUpdateFrame(b, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(f).To(BeAssignableToTypeOf(&MaxDataFrame{}))
				frame := f.(*MaxDataFrame)
				Expect(frame.ByteOffset).To(Equal(protocol.ByteCount(0xdecafbad11223344)))
			})

			It("errors on EOFs", func() {
				data := []byte{0x4,
					0xef, 0xbe, 0xad, 0xde, // stream id
					0x44, 0x33, 0x22, 0x11, 0xad, 0xfb, 0xca, 0xde, // byte offset
				}
				_, err := parseWindowUpdateFrame(bytes.NewReader(data), versionBigEndian)
				Expect(err).NotTo(HaveOccurred())
				for i := range data {
					_, err := parseWindowUpdateFrame(bytes.NewReader(data[0:i]), versionBigEndian)
					Expect(err).To(HaveOccurred())
				}
			})
		})
	})

	Context("writing", func() {
		It("has the proper min length for the stream-level WINDOW_UPDATE frame", func() {
			f := &MaxDataFrame{
				ByteOffset: 0xdeadbeef,
			}
			Expect(f.Length(versionBigEndian)).To(Equal(protocol.ByteCount(1 + 4 + 8)))
		})

		It("has the proper min length for the connection-level WINDOW_UPDATE frame", func() {
			f := &MaxDataFrame{
				ByteOffset: 0xdeadbeef,
			}
			Expect(f.Length(versionBigEndian)).To(Equal(protocol.ByteCount(1 + 4 + 8)))
		})

		Context("in big endian", func() {
			It("writes a stream-level WINDOW_UPDATE frame", func() {
				b := &bytes.Buffer{}
				f := &MaxStreamDataFrame{
					StreamID:   0xdecafbad,
					ByteOffset: 0xdeadbeefcafe1337,
				}
				err := f.Write(b, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(b.Bytes()).To(Equal([]byte{0x4,
					0xde, 0xca, 0xfb, 0xad, // stream ID 0
					0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37, // byte offset
				}))
			})

			It("writes a connection-level WINDOW_UPDATE frame", func() {
				b := &bytes.Buffer{}
				f := &MaxDataFrame{
					ByteOffset: 0xdeadbeefcafe1337,
				}
				err := f.Write(b, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(b.Bytes()).To(Equal([]byte{0x4,
					0x0, 0x0, 0x0, 0x0, // stream ID 0
					0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37, // byte offset
				}))
			})
		})
	})
})
