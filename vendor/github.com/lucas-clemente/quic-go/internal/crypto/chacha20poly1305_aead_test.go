// +build ignore

package crypto

import (
	"crypto/rand"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Chacha20poly1305", func() {
	var (
		alice, bob                       AEAD
		keyAlice, keyBob, ivAlice, ivBob []byte
	)

	BeforeEach(func() {
		keyAlice = make([]byte, 32)
		keyBob = make([]byte, 32)
		ivAlice = make([]byte, 4)
		ivBob = make([]byte, 4)
		rand.Reader.Read(keyAlice)
		rand.Reader.Read(keyBob)
		rand.Reader.Read(ivAlice)
		rand.Reader.Read(ivBob)
		var err error
		alice, err = NewAEADChacha20Poly1305(keyBob, keyAlice, ivBob, ivAlice)
		Expect(err).ToNot(HaveOccurred())
		bob, err = NewAEADChacha20Poly1305(keyAlice, keyBob, ivAlice, ivBob)
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
		Expect(b).To(HaveLen(6 + 12))
	})

	It("fails with wrong aad", func() {
		b := alice.Seal(nil, []byte("foobar"), 42, []byte("aad"))
		_, err := bob.Open(nil, b, 42, []byte("aad2"))
		Expect(err).To(HaveOccurred())
	})

	It("rejects wrong key and iv sizes", func() {
		var err error
		e := "chacha20poly1305: expected 32-byte keys and 4-byte IVs"
		_, err = NewAEADChacha20Poly1305(keyBob[1:], keyAlice, ivBob, ivAlice)
		Expect(err).To(MatchError(e))
		_, err = NewAEADChacha20Poly1305(keyBob, keyAlice[1:], ivBob, ivAlice)
		Expect(err).To(MatchError(e))
		_, err = NewAEADChacha20Poly1305(keyBob, keyAlice, ivBob[1:], ivAlice)
		Expect(err).To(MatchError(e))
		_, err = NewAEADChacha20Poly1305(keyBob, keyAlice, ivBob, ivAlice[1:])
		Expect(err).To(MatchError(e))
	})
})
