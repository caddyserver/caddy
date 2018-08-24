package crypto

import (
	"crypto/rand"
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("AES-GCM", func() {
	var (
		alice, bob                       AEAD
		keyAlice, keyBob, ivAlice, ivBob []byte
	)

	BeforeEach(func() {
		ivAlice = make([]byte, 12)
		ivBob = make([]byte, 12)
	})

	// 16 bytes for TLS_AES_128_GCM_SHA256
	// 32 bytes for TLS_AES_256_GCM_SHA384
	for _, ks := range []int{16, 32} {
		keySize := ks

		Context(fmt.Sprintf("with %d byte keys", keySize), func() {
			BeforeEach(func() {
				keyAlice = make([]byte, keySize)
				keyBob = make([]byte, keySize)
				rand.Reader.Read(keyAlice)
				rand.Reader.Read(keyBob)
				rand.Reader.Read(ivAlice)
				rand.Reader.Read(ivBob)
				var err error
				alice, err = NewAEADAESGCM(keyBob, keyAlice, ivBob, ivAlice)
				Expect(err).ToNot(HaveOccurred())
				bob, err = NewAEADAESGCM(keyAlice, keyBob, ivAlice, ivBob)
				Expect(err).ToNot(HaveOccurred())
			})

			It("seals and opens", func() {
				b := alice.Seal(nil, []byte("foobar"), 42, []byte("aad"))
				text, err := bob.Open(nil, b, 42, []byte("aad"))
				Expect(err).ToNot(HaveOccurred())
				Expect(text).To(Equal([]byte("foobar")))
			})

			It("seals and opens reverse", func() {
				b := bob.Seal(nil, []byte("foobar"), 42, []byte("aad"))
				text, err := alice.Open(nil, b, 42, []byte("aad"))
				Expect(err).ToNot(HaveOccurred())
				Expect(text).To(Equal([]byte("foobar")))
			})

			It("has the proper length", func() {
				b := bob.Seal(nil, []byte("foobar"), 42, []byte("aad"))
				Expect(b).To(HaveLen(6 + bob.Overhead()))
			})

			It("fails with wrong aad", func() {
				b := alice.Seal(nil, []byte("foobar"), 42, []byte("aad"))
				_, err := bob.Open(nil, b, 42, []byte("aad2"))
				Expect(err).To(HaveOccurred())
			})

			It("rejects wrong key and iv sizes", func() {
				e := "AES-GCM: expected 12 byte IVs"
				var err error
				_, err = NewAEADAESGCM(keyBob, keyAlice, ivBob[1:], ivAlice)
				Expect(err).To(MatchError(e))
				_, err = NewAEADAESGCM(keyBob, keyAlice, ivBob, ivAlice[1:])
				Expect(err).To(MatchError(e))
			})
		})
	}

	It("errors when an invalid key size is used", func() {
		keyAlice = make([]byte, 17)
		keyBob = make([]byte, 17)
		_, err := NewAEADAESGCM(keyBob, keyAlice, ivBob, ivAlice)
		Expect(err).To(MatchError("crypto/aes: invalid key size 17"))
	})
})
