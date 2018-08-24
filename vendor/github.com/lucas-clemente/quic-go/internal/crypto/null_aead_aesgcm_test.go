package crypto

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("NullAEAD using AES-GCM", func() {
	// values taken from https://github.com/quicwg/base-drafts/wiki/Test-Vector-for-the-Clear-Text-AEAD-key-derivation
	Context("using the test vector from the QUIC WG Wiki", func() {
		connID := protocol.ConnectionID([]byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08})

		It("computes the secrets", func() {
			clientSecret, serverSecret := computeSecrets(connID)
			Expect(clientSecret).To(Equal([]byte{
				0x83, 0x55, 0xf2, 0x1a, 0x3d, 0x8f, 0x83, 0xec,
				0xb3, 0xd0, 0xf9, 0x71, 0x08, 0xd3, 0xf9, 0x5e,
				0x0f, 0x65, 0xb4, 0xd8, 0xae, 0x88, 0xa0, 0x61,
				0x1e, 0xe4, 0x9d, 0xb0, 0xb5, 0x23, 0x59, 0x1d,
			}))
			Expect(serverSecret).To(Equal([]byte{
				0xf8, 0x0e, 0x57, 0x71, 0x48, 0x4b, 0x21, 0xcd,
				0xeb, 0xb5, 0xaf, 0xe0, 0xa2, 0x56, 0xa3, 0x17,
				0x41, 0xef, 0xe2, 0xb5, 0xc6, 0xb6, 0x17, 0xba,
				0xe1, 0xb2, 0xf1, 0x5a, 0x83, 0x04, 0x83, 0xd6,
			}))
		})

		It("computes the client key and IV", func() {
			clientSecret, _ := computeSecrets(connID)
			key, iv := computeNullAEADKeyAndIV(clientSecret)
			Expect(key).To(Equal([]byte{
				0x3a, 0xd0, 0x54, 0x2c, 0x4a, 0x85, 0x84, 0x74,
				0x00, 0x63, 0x04, 0x9e, 0x3b, 0x3c, 0xaa, 0xb2,
			}))
			Expect(iv).To(Equal([]byte{
				0xd1, 0xfd, 0x26, 0x05, 0x42, 0x75, 0x3a, 0xba,
				0x38, 0x58, 0x9b, 0xad,
			}))
		})

		It("computes the server key and IV", func() {
			_, serverSecret := computeSecrets(connID)
			key, iv := computeNullAEADKeyAndIV(serverSecret)
			Expect(key).To(Equal([]byte{
				0xbe, 0xe4, 0xc2, 0x4d, 0x2a, 0xf1, 0x33, 0x80,
				0xa9, 0xfa, 0x24, 0xa5, 0xe2, 0xba, 0x2c, 0xff,
			}))
			Expect(iv).To(Equal([]byte{
				0x25, 0xb5, 0x8e, 0x24, 0x6d, 0x9e, 0x7d, 0x5f,
				0xfe, 0x43, 0x23, 0xfe,
			}))
		})
	})

	It("seals and opens", func() {
		connectionID := protocol.ConnectionID([]byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef})
		clientAEAD, err := newNullAEADAESGCM(connectionID, protocol.PerspectiveClient)
		Expect(err).ToNot(HaveOccurred())
		serverAEAD, err := newNullAEADAESGCM(connectionID, protocol.PerspectiveServer)
		Expect(err).ToNot(HaveOccurred())

		clientMessage := clientAEAD.Seal(nil, []byte("foobar"), 42, []byte("aad"))
		m, err := serverAEAD.Open(nil, clientMessage, 42, []byte("aad"))
		Expect(err).ToNot(HaveOccurred())
		Expect(m).To(Equal([]byte("foobar")))
		serverMessage := serverAEAD.Seal(nil, []byte("raboof"), 99, []byte("daa"))
		m, err = clientAEAD.Open(nil, serverMessage, 99, []byte("daa"))
		Expect(err).ToNot(HaveOccurred())
		Expect(m).To(Equal([]byte("raboof")))
	})

	It("doesn't work if initialized with different connection IDs", func() {
		c1 := protocol.ConnectionID([]byte{0, 0, 0, 0, 0, 0, 0, 1})
		c2 := protocol.ConnectionID([]byte{0, 0, 0, 0, 0, 0, 0, 2})
		clientAEAD, err := newNullAEADAESGCM(c1, protocol.PerspectiveClient)
		Expect(err).ToNot(HaveOccurred())
		serverAEAD, err := newNullAEADAESGCM(c2, protocol.PerspectiveServer)
		Expect(err).ToNot(HaveOccurred())

		clientMessage := clientAEAD.Seal(nil, []byte("foobar"), 42, []byte("aad"))
		_, err = serverAEAD.Open(nil, clientMessage, 42, []byte("aad"))
		Expect(err).To(MatchError("cipher: message authentication failed"))
	})
})
