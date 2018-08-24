package crypto

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("ProofRsa", func() {
	It("works", func() {
		a, err := NewCurve25519KEX()
		Expect(err).ToNot(HaveOccurred())
		b, err := NewCurve25519KEX()
		Expect(err).ToNot(HaveOccurred())
		sA, err := a.CalculateSharedKey(b.PublicKey())
		Expect(err).ToNot(HaveOccurred())
		sB, err := b.CalculateSharedKey(a.PublicKey())
		Expect(err).ToNot(HaveOccurred())
		Expect(sA).To(Equal(sB))
	})

	It("rejects short public keys", func() {
		a, err := NewCurve25519KEX()
		Expect(err).ToNot(HaveOccurred())
		_, err = a.CalculateSharedKey(nil)
		Expect(err).To(MatchError("Curve25519: expected public key of 32 byte"))
	})
})
