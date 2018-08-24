package utils

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Atomic Bool", func() {
	var a *AtomicBool

	BeforeEach(func() {
		a = &AtomicBool{}
	})

	It("has the right default value", func() {
		Expect(a.Get()).To(BeFalse())
	})

	It("sets the value to true", func() {
		a.Set(true)
		Expect(a.Get()).To(BeTrue())
	})

	It("sets the value to false", func() {
		a.Set(true)
		a.Set(false)
		Expect(a.Get()).To(BeFalse())
	})
})
