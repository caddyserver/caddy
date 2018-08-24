package crypto

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("NullAEAD using FNV128a", func() {
	aad := []byte("All human beings are born free and equal in dignity and rights.")
	plainText := []byte("They are endowed with reason and conscience and should act towards one another in a spirit of brotherhood.")
	hash36 := []byte{0x98, 0x9b, 0x33, 0x3f, 0xe8, 0xde, 0x32, 0x5c, 0xa6, 0x7f, 0x9c, 0xf7}

	var aeadServer AEAD
	var aeadClient AEAD

	BeforeEach(func() {
		aeadServer = &nullAEADFNV128a{protocol.PerspectiveServer}
		aeadClient = &nullAEADFNV128a{protocol.PerspectiveClient}
	})

	It("seals and opens, client => server", func() {
		cipherText := aeadClient.Seal(nil, plainText, 0, aad)
		res, err := aeadServer.Open(nil, cipherText, 0, aad)
		Expect(err).ToNot(HaveOccurred())
		Expect(res).To(Equal([]byte("They are endowed with reason and conscience and should act towards one another in a spirit of brotherhood.")))
	})

	It("seals and opens, server => client", func() {
		cipherText := aeadServer.Seal(nil, plainText, 0, aad)
		res, err := aeadClient.Open(nil, cipherText, 0, aad)
		Expect(err).ToNot(HaveOccurred())
		Expect(res).To(Equal([]byte("They are endowed with reason and conscience and should act towards one another in a spirit of brotherhood.")))
	})

	It("rejects short ciphertexts", func() {
		_, err := aeadServer.Open(nil, nil, 0, nil)
		Expect(err).To(MatchError("NullAEAD: ciphertext cannot be less than 12 bytes long"))
	})

	It("seals in-place", func() {
		buf := make([]byte, 6, 12+6)
		copy(buf, []byte("foobar"))
		res := aeadServer.Seal(buf[0:0], buf, 0, nil)
		buf = buf[:12+6]
		Expect(buf[12:]).To(Equal([]byte("foobar")))
		Expect(res[12:]).To(Equal([]byte("foobar")))
	})

	It("fails", func() {
		cipherText := append(append(hash36, plainText...), byte(0x42))
		_, err := aeadClient.Open(nil, cipherText, 0, aad)
		Expect(err).To(HaveOccurred())
	})
})
