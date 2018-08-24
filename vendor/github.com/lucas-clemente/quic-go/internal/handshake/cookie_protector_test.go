package handshake

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Cookie Protector", func() {
	var cp cookieProtector

	BeforeEach(func() {
		var err error
		cp, err = newCookieProtector()
		Expect(err).ToNot(HaveOccurred())
	})

	It("encodes and decodes tokens", func() {
		token, err := cp.NewToken([]byte("foobar"))
		Expect(err).ToNot(HaveOccurred())
		Expect(token).ToNot(ContainSubstring("foobar"))
		decoded, err := cp.DecodeToken(token)
		Expect(err).ToNot(HaveOccurred())
		Expect(decoded).To(Equal([]byte("foobar")))
	})

	It("fails deconding invalid tokens", func() {
		token, err := cp.NewToken([]byte("foobar"))
		Expect(err).ToNot(HaveOccurred())
		token = token[1:] // remove the first byte
		_, err = cp.DecodeToken(token)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("message authentication failed"))
	})

	It("errors when decoding too short tokens", func() {
		_, err := cp.DecodeToken([]byte("foobar"))
		Expect(err).To(MatchError("Token too short: 6"))
	})
})
