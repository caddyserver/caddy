package handshake

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/qerr"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Handshake Message", func() {
	Context("when parsing", func() {
		It("parses sample CHLO message", func() {
			msg, err := ParseHandshakeMessage(bytes.NewReader(sampleCHLO))
			Expect(err).ToNot(HaveOccurred())
			Expect(msg.Tag).To(Equal(TagCHLO))
			Expect(msg.Data).To(Equal(sampleCHLOMap))
		})

		It("rejects large numbers of pairs", func() {
			r := bytes.NewReader([]byte("CHLO\xff\xff\xff\xff"))
			_, err := ParseHandshakeMessage(r)
			Expect(err).To(MatchError(qerr.CryptoTooManyEntries))
		})

		It("rejects too long values", func() {
			r := bytes.NewReader([]byte{
				'C', 'H', 'L', 'O',
				1, 0, 0, 0,
				0, 0, 0, 0,
				0xff, 0xff, 0xff, 0xff,
			})
			_, err := ParseHandshakeMessage(r)
			Expect(err).To(MatchError(qerr.Error(qerr.CryptoInvalidValueLength, "value too long")))
		})
	})

	Context("when writing", func() {
		It("writes sample message", func() {
			b := &bytes.Buffer{}
			HandshakeMessage{Tag: TagCHLO, Data: sampleCHLOMap}.Write(b)
			Expect(b.Bytes()).To(Equal(sampleCHLO))
		})
	})

	Context("string representation", func() {
		It("has a string representation", func() {
			str := HandshakeMessage{
				Tag: TagSHLO,
				Data: map[Tag][]byte{
					TagAEAD: []byte("foobar"),
					TagEXPY: []byte("raboof"),
				},
			}.String()
			Expect(str[:4]).To(Equal("SHLO"))
			Expect(str).To(ContainSubstring("AEAD: \"foobar\""))
			Expect(str).To(ContainSubstring("EXPY: \"raboof\""))
		})

		It("lists padding separately", func() {
			str := HandshakeMessage{
				Tag: TagSHLO,
				Data: map[Tag][]byte{
					TagPAD: bytes.Repeat([]byte{0}, 1337),
				},
			}.String()
			Expect(str).To(ContainSubstring("PAD"))
			Expect(str).To(ContainSubstring("1337 bytes"))
		})
	})
})
