package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("MAX_STREAM_ID frame", func() {
	Context("parsing", func() {
		It("accepts sample frame", func() {
			data := []byte{0x6}
			data = append(data, encodeVarInt(0xdecafbad)...)
			b := bytes.NewReader(data)
			f, err := parseMaxStreamIDFrame(b, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(f.StreamID).To(Equal(protocol.StreamID(0xdecafbad)))
			Expect(b.Len()).To(BeZero())
		})

		It("errors on EOFs", func() {
			data := []byte{0x06}
			data = append(data, encodeVarInt(0xdeadbeefcafe13)...)
			_, err := parseMaxStreamIDFrame(bytes.NewReader(data), protocol.VersionWhatever)
			Expect(err).NotTo(HaveOccurred())
			for i := range data {
				_, err := parseMaxStreamIDFrame(bytes.NewReader(data[0:i]), protocol.VersionWhatever)
				Expect(err).To(HaveOccurred())
			}
		})
	})

	Context("writing", func() {
		It("writes a sample frame", func() {
			b := &bytes.Buffer{}
			frame := MaxStreamIDFrame{StreamID: 0x12345678}
			frame.Write(b, protocol.VersionWhatever)
			expected := []byte{0x6}
			expected = append(expected, encodeVarInt(0x12345678)...)
			Expect(b.Bytes()).To(Equal(expected))
		})

		It("has the correct min length", func() {
			frame := MaxStreamIDFrame{StreamID: 0x1337}
			Expect(frame.Length(protocol.VersionWhatever)).To(Equal(1 + utils.VarIntLen(0x1337)))
		})
	})
})
