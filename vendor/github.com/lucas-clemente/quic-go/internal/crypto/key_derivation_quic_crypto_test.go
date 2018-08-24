package crypto

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("QUIC Crypto Key Derivation", func() {
	// Context("chacha20poly1305", func() {
	// 	It("derives non-fs keys", func() {
	// 		aead, err := DeriveKeysChacha20(
	// 			protocol.Version32,
	// 			false,
	// 			[]byte("0123456789012345678901"),
	// 			[]byte("nonce"),
	// 			protocol.ConnectionID(42),
	// 			[]byte("chlo"),
	// 			[]byte("scfg"),
	// 			[]byte("cert"),
	// 			nil,
	// 		)
	// 		Expect(err).ToNot(HaveOccurred())
	// 		chacha := aead.(*aeadChacha20Poly1305)
	// 		// If the IVs match, the keys will match too, since the keys are read earlier
	// 		Expect(chacha.myIV).To(Equal([]byte{0xf0, 0xf5, 0x4c, 0xa8}))
	// 		Expect(chacha.otherIV).To(Equal([]byte{0x75, 0xd8, 0xa2, 0x8d}))
	// 	})
	//
	// 	It("derives fs keys", func() {
	// 		aead, err := DeriveKeysChacha20(
	// 			protocol.Version32,
	// 			true,
	// 			[]byte("0123456789012345678901"),
	// 			[]byte("nonce"),
	// 			protocol.ConnectionID(42),
	// 			[]byte("chlo"),
	// 			[]byte("scfg"),
	// 			[]byte("cert"),
	// 			nil,
	// 		)
	// 		Expect(err).ToNot(HaveOccurred())
	// 		chacha := aead.(*aeadChacha20Poly1305)
	// 		// If the IVs match, the keys will match too, since the keys are read earlier
	// 		Expect(chacha.myIV).To(Equal([]byte{0xf5, 0x73, 0x11, 0x79}))
	// 		Expect(chacha.otherIV).To(Equal([]byte{0xf7, 0x26, 0x4d, 0x2c}))
	// 	})
	//
	// 	It("does not use diversification nonces in FS key derivation", func() {
	// 		aead, err := DeriveKeysChacha20(
	// 			protocol.Version33,
	// 			true,
	// 			[]byte("0123456789012345678901"),
	// 			[]byte("nonce"),
	// 			protocol.ConnectionID(42),
	// 			[]byte("chlo"),
	// 			[]byte("scfg"),
	// 			[]byte("cert"),
	// 			[]byte("divnonce"),
	// 		)
	// 		Expect(err).ToNot(HaveOccurred())
	// 		chacha := aead.(*aeadChacha20Poly1305)
	// 		// If the IVs match, the keys will match too, since the keys are read earlier
	// 		Expect(chacha.myIV).To(Equal([]byte{0xf5, 0x73, 0x11, 0x79}))
	// 		Expect(chacha.otherIV).To(Equal([]byte{0xf7, 0x26, 0x4d, 0x2c}))
	// 	})
	//
	// 	It("uses diversification nonces in initial key derivation", func() {
	// 		aead, err := DeriveKeysChacha20(
	// 			protocol.Version33,
	// 			false,
	// 			[]byte("0123456789012345678901"),
	// 			[]byte("nonce"),
	// 			protocol.ConnectionID(42),
	// 			[]byte("chlo"),
	// 			[]byte("scfg"),
	// 			[]byte("cert"),
	// 			[]byte("divnonce"),
	// 		)
	// 		Expect(err).ToNot(HaveOccurred())
	// 		chacha := aead.(*aeadChacha20Poly1305)
	// 		// If the IVs match, the keys will match too, since the keys are read earlier
	// 		Expect(chacha.myIV).To(Equal([]byte{0xc4, 0x12, 0x25, 0x64}))
	// 		Expect(chacha.otherIV).To(Equal([]byte{0x75, 0xd8, 0xa2, 0x8d}))
	// 	})
	// })

	Context("AES-GCM", func() {
		It("derives non-forward secure keys", func() {
			aead, err := DeriveQuicCryptoAESKeys(
				false,
				[]byte("0123456789012345678901"),
				[]byte("nonce"),
				protocol.ConnectionID([]byte{42, 0, 0, 0, 0, 0, 0, 0}),
				[]byte("chlo"),
				[]byte("scfg"),
				[]byte("cert"),
				[]byte("divnonce"),
				protocol.PerspectiveServer,
			)
			Expect(err).ToNot(HaveOccurred())
			aesgcm := aead.(*aeadAESGCM12)
			// If the IVs match, the keys will match too, since the keys are read earlier
			Expect(aesgcm.myIV).To(Equal([]byte{0x1c, 0xec, 0xac, 0x9b}))
			Expect(aesgcm.otherIV).To(Equal([]byte{0x64, 0xef, 0x3c, 0x9}))
		})

		It("uses the diversification nonce when generating non-forwared secure keys", func() {
			aead1, err := DeriveQuicCryptoAESKeys(
				false,
				[]byte("0123456789012345678901"),
				[]byte("nonce"),
				protocol.ConnectionID([]byte{42, 0, 0, 0, 0, 0, 0, 0}),
				[]byte("chlo"),
				[]byte("scfg"),
				[]byte("cert"),
				[]byte("divnonce"),
				protocol.PerspectiveServer,
			)
			Expect(err).ToNot(HaveOccurred())
			aead2, err := DeriveQuicCryptoAESKeys(
				false,
				[]byte("0123456789012345678901"),
				[]byte("nonce"),
				protocol.ConnectionID([]byte{42, 0, 0, 0, 0, 0, 0, 0}),
				[]byte("chlo"),
				[]byte("scfg"),
				[]byte("cert"),
				[]byte("ecnonvid"),
				protocol.PerspectiveServer,
			)
			Expect(err).ToNot(HaveOccurred())
			aesgcm1 := aead1.(*aeadAESGCM12)
			aesgcm2 := aead2.(*aeadAESGCM12)
			Expect(aesgcm1.myIV).ToNot(Equal(aesgcm2.myIV))
			Expect(aesgcm1.otherIV).To(Equal(aesgcm2.otherIV))
		})

		It("derives non-forward secure keys, for the other side", func() {
			aead, err := DeriveQuicCryptoAESKeys(
				false,
				[]byte("0123456789012345678901"),
				[]byte("nonce"),
				protocol.ConnectionID([]byte{42, 0, 0, 0, 0, 0, 0, 0}),
				[]byte("chlo"),
				[]byte("scfg"),
				[]byte("cert"),
				[]byte("divnonce"),
				protocol.PerspectiveClient,
			)
			Expect(err).ToNot(HaveOccurred())
			aesgcm := aead.(*aeadAESGCM12)
			// If the IVs match, the keys will match too, since the keys are read earlier
			Expect(aesgcm.otherIV).To(Equal([]byte{0x1c, 0xec, 0xac, 0x9b}))
			Expect(aesgcm.myIV).To(Equal([]byte{0x64, 0xef, 0x3c, 0x9}))
		})

		It("derives forward secure keys", func() {
			aead, err := DeriveQuicCryptoAESKeys(
				true,
				[]byte("0123456789012345678901"),
				[]byte("nonce"),
				protocol.ConnectionID([]byte{42, 0, 0, 0, 0, 0, 0, 0}),
				[]byte("chlo"),
				[]byte("scfg"),
				[]byte("cert"),
				nil,
				protocol.PerspectiveServer,
			)
			Expect(err).ToNot(HaveOccurred())
			aesgcm := aead.(*aeadAESGCM12)
			// If the IVs match, the keys will match too, since the keys are read earlier
			Expect(aesgcm.myIV).To(Equal([]byte{0x7, 0xad, 0xab, 0xb8}))
			Expect(aesgcm.otherIV).To(Equal([]byte{0xf2, 0x7a, 0xcc, 0x42}))
		})

		It("does not use div-nonce for FS key derivation", func() {
			aead, err := DeriveQuicCryptoAESKeys(
				true,
				[]byte("0123456789012345678901"),
				[]byte("nonce"),
				protocol.ConnectionID([]byte{42, 0, 0, 0, 0, 0, 0, 0}),
				[]byte("chlo"),
				[]byte("scfg"),
				[]byte("cert"),
				[]byte("divnonce"),
				protocol.PerspectiveServer,
			)
			Expect(err).ToNot(HaveOccurred())
			aesgcm := aead.(*aeadAESGCM12)
			// If the IVs match, the keys will match too, since the keys are read earlier
			Expect(aesgcm.myIV).To(Equal([]byte{0x7, 0xad, 0xab, 0xb8}))
			Expect(aesgcm.otherIV).To(Equal([]byte{0xf2, 0x7a, 0xcc, 0x42}))
		})
	})
})
