package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("STREAM_BLOCKED frame", func() {
	Context("parsing", func() {
		It("accepts sample frame", func() {
			data := []byte{0x9}
			data = append(data, encodeVarInt(0xdeadbeef)...) // stream ID
			data = append(data, encodeVarInt(0xdecafbad)...) // offset
			b := bytes.NewReader(data)
			frame, err := parseStreamBlockedFrame(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.StreamID).To(Equal(protocol.StreamID(0xdeadbeef)))
			Expect(frame.Offset).To(Equal(protocol.ByteCount(0xdecafbad)))
			Expect(b.Len()).To(BeZero())
		})

		It("errors on EOFs", func() {
			data := []byte{0x9}
			data = append(data, encodeVarInt(0xdeadbeef)...)
			data = append(data, encodeVarInt(0xc0010ff)...)
			_, err := parseStreamBlockedFrame(bytes.NewReader(data), versionIETFFrames)
			Expect(err).NotTo(HaveOccurred())
			for i := range data {
				_, err := parseStreamBlockedFrame(bytes.NewReader(data[0:i]), versionIETFFrames)
				Expect(err).To(HaveOccurred())
			}
		})
	})

	Context("writing", func() {
		It("has proper min length", func() {
			f := &StreamBlockedFrame{
				StreamID: 0x1337,
				Offset:   0xdeadbeef,
			}
			Expect(f.Length(0)).To(Equal(1 + utils.VarIntLen(0x1337) + utils.VarIntLen(0xdeadbeef)))
		})

		It("writes a sample frame", func() {
			b := &bytes.Buffer{}
			f := &StreamBlockedFrame{
				StreamID: 0xdecafbad,
				Offset:   0x1337,
			}
			err := f.Write(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			expected := []byte{0x9}
			expected = append(expected, encodeVarInt(uint64(f.StreamID))...)
			expected = append(expected, encodeVarInt(uint64(f.Offset))...)
			Expect(b.Bytes()).To(Equal(expected))
		})
	})
})
