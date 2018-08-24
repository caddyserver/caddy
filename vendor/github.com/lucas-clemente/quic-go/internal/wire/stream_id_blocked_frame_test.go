package wire

import (
	"bytes"
	"io"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("STREAM_ID_BLOCKED frame", func() {
	Context("parsing", func() {
		It("accepts sample frame", func() {
			expected := []byte{0xa}
			expected = append(expected, encodeVarInt(0xdecafbad)...)
			b := bytes.NewReader(expected)
			frame, err := parseStreamIDBlockedFrame(b, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.StreamID).To(Equal(protocol.StreamID(0xdecafbad)))
			Expect(b.Len()).To(BeZero())
		})

		It("errors on EOFs", func() {
			data := []byte{0xa}
			data = append(data, encodeVarInt(0x12345678)...)
			_, err := parseStreamIDBlockedFrame(bytes.NewReader(data), versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			for i := range data {
				_, err := parseStreamIDBlockedFrame(bytes.NewReader(data[:i]), versionIETFFrames)
				Expect(err).To(MatchError(io.EOF))
			}
		})
	})

	Context("writing", func() {
		It("writes a sample frame", func() {
			b := &bytes.Buffer{}
			frame := StreamIDBlockedFrame{StreamID: 0xdeadbeefcafe}
			err := frame.Write(b, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			expected := []byte{0xa}
			expected = append(expected, encodeVarInt(0xdeadbeefcafe)...)
			Expect(b.Bytes()).To(Equal(expected))
		})

		It("has the correct min length", func() {
			frame := StreamIDBlockedFrame{StreamID: 0x123456}
			Expect(frame.Length(0)).To(Equal(protocol.ByteCount(1) + utils.VarIntLen(0x123456)))
		})
	})
})
