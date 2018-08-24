package wire

import (
	"bytes"
	"io"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("PATH_RESPONSE frame", func() {
	Context("when parsing", func() {
		It("accepts sample frame", func() {
			b := bytes.NewReader([]byte{0x0f, 1, 2, 3, 4, 5, 6, 7, 8})
			f, err := parsePathResponseFrame(b, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(b.Len()).To(BeZero())
			Expect(f.Data).To(Equal([8]byte{1, 2, 3, 4, 5, 6, 7, 8}))
		})

		It("errors on EOFs", func() {
			data := []byte{0x0f, 1, 2, 3, 4, 5, 6, 7, 8}
			_, err := parsePathResponseFrame(bytes.NewReader(data), versionIETFFrames)
			Expect(err).NotTo(HaveOccurred())
			for i := range data {
				_, err := parsePathResponseFrame(bytes.NewReader(data[0:i]), versionIETFFrames)
				Expect(err).To(MatchError(io.EOF))
			}
		})
	})

	Context("when writing", func() {
		It("writes a sample frame", func() {
			b := &bytes.Buffer{}
			frame := PathResponseFrame{Data: [8]byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37}}
			err := frame.Write(b, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(b.Bytes()).To(Equal([]byte{0x0f, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37}))
		})

		It("has the correct min length", func() {
			frame := PathResponseFrame{}
			Expect(frame.Length(protocol.VersionWhatever)).To(Equal(protocol.ByteCount(9)))
		})
	})
})
