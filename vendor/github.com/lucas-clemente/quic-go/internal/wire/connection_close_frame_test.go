package wire

import (
	"bytes"
	"io"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("CONNECTION_CLOSE Frame", func() {
	Context("when parsing", func() {
		Context("in varint encoding", func() {
			It("accepts sample frame", func() {
				data := []byte{0x2, 0x0, 0x19}
				data = append(data, encodeVarInt(0x1b)...) // reason phrase length
				data = append(data, []byte{
					'N', 'o', ' ', 'r', 'e', 'c', 'e', 'n', 't', ' ', 'n', 'e', 't', 'w', 'o', 'r', 'k', ' ', 'a', 'c', 't', 'i', 'v', 'i', 't', 'y', '.',
				}...)
				b := bytes.NewReader(data)
				frame, err := parseConnectionCloseFrame(b, versionIETFFrames)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.ErrorCode).To(Equal(qerr.ErrorCode(0x19)))
				Expect(frame.ReasonPhrase).To(Equal("No recent network activity."))
				Expect(b.Len()).To(BeZero())
			})

			It("rejects long reason phrases", func() {
				data := []byte{0x2, 0xca, 0xfe}
				data = append(data, encodeVarInt(0xffff)...) // reason phrase length
				b := bytes.NewReader(data)
				_, err := parseConnectionCloseFrame(b, versionIETFFrames)
				Expect(err).To(MatchError(io.EOF))
			})

			It("errors on EOFs", func() {
				data := []byte{0x2, 0x0, 0x19}
				data = append(data, encodeVarInt(0x1b)...) // reason phrase length
				data = append(data, []byte{
					'N', 'o', ' ', 'r', 'e', 'c', 'e', 'n', 't', ' ', 'n', 'e', 't', 'w', 'o', 'r', 'k', ' ', 'a', 'c', 't', 'i', 'v', 'i', 't', 'y', '.',
				}...)
				_, err := parseConnectionCloseFrame(bytes.NewReader(data), versionIETFFrames)
				Expect(err).NotTo(HaveOccurred())
				for i := range data {
					_, err := parseConnectionCloseFrame(bytes.NewReader(data[0:i]), versionIETFFrames)
					Expect(err).To(HaveOccurred())
				}
			})

			It("parses a frame without a reason phrase", func() {
				data := []byte{0x2, 0xca, 0xfe}
				data = append(data, encodeVarInt(0)...)
				b := bytes.NewReader(data)
				frame, err := parseConnectionCloseFrame(b, versionIETFFrames)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.ReasonPhrase).To(BeEmpty())
				Expect(b.Len()).To(BeZero())
			})
		})

		Context("in big endian", func() {
			It("accepts sample frame", func() {
				b := bytes.NewReader([]byte{0x2,
					0x0, 0x0, 0x0, 0x19, // error code
					0x0, 0x1b, // reason phrase length
					'N', 'o', ' ', 'r', 'e', 'c', 'e', 'n', 't', ' ', 'n', 'e', 't', 'w', 'o', 'r', 'k', ' ', 'a', 'c', 't', 'i', 'v', 'i', 't', 'y', '.',
				})
				frame, err := parseConnectionCloseFrame(b, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.ErrorCode).To(Equal(qerr.ErrorCode(0x19)))
				Expect(frame.ReasonPhrase).To(Equal("No recent network activity."))
				Expect(b.Len()).To(BeZero())
			})

			It("rejects long reason phrases", func() {
				b := bytes.NewReader([]byte{0x2,
					0xad, 0xfb, 0xca, 0xde, // error code
					0xff, 0x0, // reason phrase length
				})
				_, err := parseConnectionCloseFrame(b, versionBigEndian)
				Expect(err).To(MatchError(io.EOF))
			})

			It("errors on EOFs", func() {
				data := []byte{0x40,
					0x19, 0x0, 0x0, 0x0, // error code
					0x0, 0x1b, // reason phrase length
					'N', 'o', ' ', 'r', 'e', 'c', 'e', 'n', 't', ' ', 'n', 'e', 't', 'w', 'o', 'r', 'k', ' ', 'a', 'c', 't', 'i', 'v', 'i', 't', 'y', '.',
				}
				_, err := parseConnectionCloseFrame(bytes.NewReader(data), versionBigEndian)
				Expect(err).NotTo(HaveOccurred())
				for i := range data {
					_, err := parseConnectionCloseFrame(bytes.NewReader(data[0:i]), versionBigEndian)
					Expect(err).To(HaveOccurred())
				}
			})

			It("parses a frame without a reason phrase", func() {
				b := bytes.NewReader([]byte{0x2,
					0xad, 0xfb, 0xca, 0xde, // error code
					0x0, 0x0, // reason phrase length
				})
				frame, err := parseConnectionCloseFrame(b, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.ReasonPhrase).To(BeEmpty())
				Expect(b.Len()).To(BeZero())
			})
		})
	})

	Context("when writing", func() {
		Context("in varint encoding", func() {
			It("writes a frame without a ReasonPhrase", func() {
				b := &bytes.Buffer{}
				frame := &ConnectionCloseFrame{
					ErrorCode: 0xbeef,
				}
				err := frame.Write(b, versionIETFFrames)
				Expect(err).ToNot(HaveOccurred())
				expected := []byte{0x2, 0xbe, 0xef}
				expected = append(expected, encodeVarInt(0)...)
				Expect(b.Bytes()).To(Equal(expected))
			})

			It("writes a frame with a ReasonPhrase", func() {
				b := &bytes.Buffer{}
				frame := &ConnectionCloseFrame{
					ErrorCode:    0xdead,
					ReasonPhrase: "foobar",
				}
				err := frame.Write(b, versionIETFFrames)
				Expect(err).ToNot(HaveOccurred())
				expected := []byte{0x2, 0xde, 0xad}
				expected = append(expected, encodeVarInt(6)...)
				expected = append(expected, []byte{'f', 'o', 'o', 'b', 'a', 'r'}...)
				Expect(b.Bytes()).To(Equal(expected))
			})

			It("has proper min length", func() {
				b := &bytes.Buffer{}
				f := &ConnectionCloseFrame{
					ErrorCode:    0xcafe,
					ReasonPhrase: "foobar",
				}
				err := f.Write(b, versionIETFFrames)
				Expect(err).ToNot(HaveOccurred())
				Expect(f.Length(versionIETFFrames)).To(Equal(protocol.ByteCount(b.Len())))
			})
		})

		Context("in big endian", func() {
			It("writes a frame without a ReasonPhrase", func() {
				b := &bytes.Buffer{}
				frame := &ConnectionCloseFrame{
					ErrorCode: 0xdeadbeef,
				}
				err := frame.Write(b, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(b.Len()).To(Equal(1 + 2 + 4))
				Expect(b.Bytes()).To(Equal([]byte{0x2,
					0xde, 0xad, 0xbe, 0xef, // error code
					0x0, 0x0, // reason phrase length
				}))
			})

			It("writes a frame with a ReasonPhrase", func() {
				b := &bytes.Buffer{}
				frame := &ConnectionCloseFrame{
					ErrorCode:    0xdeadbeef,
					ReasonPhrase: "foobar",
				}
				err := frame.Write(b, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(b.Len()).To(Equal(1 + 2 + 4 + len(frame.ReasonPhrase)))
				Expect(b.Bytes()).To(Equal([]byte{0x2,
					0xde, 0xad, 0xbe, 0xef, // error code
					0x0, 0x6, // reason phrase length
					'f', 'o', 'o', 'b', 'a', 'r',
				}))
			})

			It("has proper min length", func() {
				b := &bytes.Buffer{}
				f := &ConnectionCloseFrame{
					ErrorCode:    0xcafe,
					ReasonPhrase: "foobar",
				}
				err := f.Write(b, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(f.Length(versionBigEndian)).To(Equal(protocol.ByteCount(b.Len())))
			})
		})
	})
})
