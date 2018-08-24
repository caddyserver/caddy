package wire

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("ACK range", func() {
	It("returns the length", func() {
		Expect(AckRange{Smallest: 10, Largest: 10}.Len()).To(BeEquivalentTo(1))
		Expect(AckRange{Smallest: 10, Largest: 13}.Len()).To(BeEquivalentTo(4))
	})
})
