package handshake

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("TLS extension body", func() {
	var extBody *tlsExtensionBody

	BeforeEach(func() {
		extBody = &tlsExtensionBody{}
	})

	It("has the right TLS extension type", func() {
		Expect(extBody.Type()).To(BeEquivalentTo(quicTLSExtensionType))
	})

	It("saves the body when unmarshalling", func() {
		n, err := extBody.Unmarshal([]byte("foobar"))
		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(6))
		Expect(extBody.data).To(Equal([]byte("foobar")))
	})

	It("returns the body when marshalling", func() {
		extBody.data = []byte("foo")
		data, err := extBody.Marshal()
		Expect(err).ToNot(HaveOccurred())
		Expect(data).To(Equal([]byte("foo")))
	})
})
