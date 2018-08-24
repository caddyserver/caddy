package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("MAX_DATA frame", func() {
	Context("when parsing", func() {
		It("accepts sample frame", func() {
			data := []byte{0x4}
			data = append(data, encodeVarInt(0xdecafbad123456)...) // byte offset
			b := bytes.NewReader(data)
			frame, err := parseMaxDataFrame(b, versionBigEndian)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.ByteOffset).To(Equal(protocol.ByteCount(0xdecafbad123456)))
			Expect(b.Len()).To(BeZero())
		})

		It("errors on EOFs", func() {
			data := []byte{0x4}
			data = append(data, encodeVarInt(0xdecafbad1234567)...) // byte offset
			_, err := parseMaxDataFrame(bytes.NewReader(data), versionIETFFrames)
			Expect(err).NotTo(HaveOccurred())
			for i := range data {
				_, err := parseMaxDataFrame(bytes.NewReader(data[0:i]), versionIETFFrames)
				Expect(err).To(HaveOccurred())
			}
		})
	})

	Context("writing", func() {
		It("has proper min length", func() {
			f := &MaxDataFrame{
				ByteOffset: 0xdeadbeef,
			}
			Expect(f.Length(versionIETFFrames)).To(Equal(1 + utils.VarIntLen(0xdeadbeef)))
		})

		It("writes a MAX_DATA frame", func() {
			b := &bytes.Buffer{}
			f := &MaxDataFrame{
				ByteOffset: 0xdeadbeefcafe,
			}
			err := f.Write(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			expected := []byte{0x4}
			expected = append(expected, encodeVarInt(0xdeadbeefcafe)...)
			Expect(b.Bytes()).To(Equal(expected))
		})
	})
})
