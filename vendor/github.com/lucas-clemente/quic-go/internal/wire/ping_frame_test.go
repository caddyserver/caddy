package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("PingFrame", func() {
	Context("when parsing", func() {
		It("accepts sample frame", func() {
			b := bytes.NewReader([]byte{0x07})
			_, err := parsePingFrame(b, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(b.Len()).To(BeZero())
		})

		It("errors on EOFs", func() {
			_, err := parsePingFrame(bytes.NewReader(nil), protocol.VersionWhatever)
			Expect(err).To(HaveOccurred())
		})
	})

	Context("when writing", func() {
		It("writes a sample frame", func() {
			b := &bytes.Buffer{}
			frame := PingFrame{}
			frame.Write(b, protocol.VersionWhatever)
			Expect(b.Bytes()).To(Equal([]byte{0x07}))
		})

		It("has the correct min length", func() {
			frame := PingFrame{}
			Expect(frame.Length(0)).To(Equal(protocol.ByteCount(1)))
		})
	})
})
