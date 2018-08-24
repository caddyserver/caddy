package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("legacy BLOCKED Frame", func() {
	Context("when parsing", func() {
		It("accepts sample frame for a stream", func() {
			b := bytes.NewReader([]byte{0x5, 0xde, 0xad, 0xbe, 0xef})
			f, err := parseBlockedFrameLegacy(b, versionBigEndian)
			Expect(err).ToNot(HaveOccurred())
			Expect(f).To(BeAssignableToTypeOf(&StreamBlockedFrame{}))
			frame := f.(*StreamBlockedFrame)
			Expect(frame.StreamID).To(Equal(protocol.StreamID(0xdeadbeef)))
		})

		It("accepts sample frame for the connection", func() {
			b := bytes.NewReader([]byte{0x5, 0x0, 0x0, 0x0, 0x0})
			f, err := parseBlockedFrameLegacy(b, versionBigEndian)
			Expect(err).ToNot(HaveOccurred())
			Expect(f).To(BeAssignableToTypeOf(&BlockedFrame{}))
		})
	})

	It("errors on EOFs", func() {
		data := []byte{0x5, 0xef, 0xbe, 0xad, 0xde}
		_, err := parseBlockedFrameLegacy(bytes.NewReader(data), protocol.VersionWhatever)
		Expect(err).NotTo(HaveOccurred())
		for i := range data {
			_, err := parseBlockedFrameLegacy(bytes.NewReader(data[0:i]), protocol.VersionWhatever)
			Expect(err).To(HaveOccurred())
		}
	})

	Context("when writing", func() {
		It("writes a BLOCKED frame for a stream", func() {
			b := &bytes.Buffer{}
			frame := StreamBlockedFrame{StreamID: 0x1337}
			frame.Write(b, versionBigEndian)
			Expect(b.Bytes()).To(Equal([]byte{0x5, 0x0, 0x0, 0x13, 0x37}))
		})

		It("has the correct min length for a BLOCKED frame for a stream", func() {
			frame := StreamBlockedFrame{StreamID: 3}
			Expect(frame.Length(versionBigEndian)).To(Equal(protocol.ByteCount(5)))
		})

		It("writes a BLOCKED frame for the connection", func() {
			b := &bytes.Buffer{}
			frame := BlockedFrame{}
			frame.Write(b, versionBigEndian)
			Expect(b.Bytes()).To(Equal([]byte{0x5, 0x0, 0x0, 0x0, 0x0}))
		})

		It("has the correct min length for a BLOCKED frame for the connection", func() {
			frame := BlockedFrame{}
			Expect(frame.Length(versionBigEndian)).To(Equal(protocol.ByteCount(5)))
		})
	})
})
