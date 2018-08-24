package protocol

import (
	"bytes"
	"io"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Connection ID generation", func() {
	It("generates random connection IDs", func() {
		c1, err := GenerateConnectionID(8)
		Expect(err).ToNot(HaveOccurred())
		Expect(c1).ToNot(BeZero())
		c2, err := GenerateConnectionID(8)
		Expect(err).ToNot(HaveOccurred())
		Expect(c1).ToNot(Equal(c2))
	})

	It("generates connection IDs with the requested length", func() {
		c, err := GenerateConnectionID(5)
		Expect(err).ToNot(HaveOccurred())
		Expect(c.Len()).To(Equal(5))
	})

	It("generates random length destination connection IDs", func() {
		var has8ByteConnID, has18ByteConnID bool
		for i := 0; i < 1000; i++ {
			c, err := GenerateConnectionIDForInitial()
			Expect(err).ToNot(HaveOccurred())
			Expect(c.Len()).To(BeNumerically(">=", 8))
			Expect(c.Len()).To(BeNumerically("<=", 18))
			if c.Len() == 8 {
				has8ByteConnID = true
			}
			if c.Len() == 18 {
				has18ByteConnID = true
			}
		}
		Expect(has8ByteConnID).To(BeTrue())
		Expect(has18ByteConnID).To(BeTrue())
	})

	It("says if connection IDs are equal", func() {
		c1 := ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
		c2 := ConnectionID{8, 7, 6, 5, 4, 3, 2, 1}
		Expect(c1.Equal(c1)).To(BeTrue())
		Expect(c2.Equal(c2)).To(BeTrue())
		Expect(c1.Equal(c2)).To(BeFalse())
		Expect(c2.Equal(c1)).To(BeFalse())
	})

	It("reads the connection ID", func() {
		buf := bytes.NewBuffer([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9})
		c, err := ReadConnectionID(buf, 9)
		Expect(err).ToNot(HaveOccurred())
		Expect(c.Bytes()).To(Equal([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9}))
	})

	It("returns io.EOF if there's not enough data to read", func() {
		buf := bytes.NewBuffer([]byte{1, 2, 3, 4})
		_, err := ReadConnectionID(buf, 5)
		Expect(err).To(MatchError(io.EOF))
	})

	It("returns nil for a 0 length connection ID", func() {
		buf := bytes.NewBuffer([]byte{1, 2, 3, 4})
		c, err := ReadConnectionID(buf, 0)
		Expect(err).ToNot(HaveOccurred())
		Expect(c).To(BeNil())
	})

	It("returns the length", func() {
		c := ConnectionID{1, 2, 3, 4, 5, 6, 7}
		Expect(c.Len()).To(Equal(7))
	})

	It("has 0 length for the default value", func() {
		var c ConnectionID
		Expect(c.Len()).To(BeZero())
	})

	It("returns the bytes", func() {
		c := ConnectionID([]byte{1, 2, 3, 4, 5, 6, 7})
		Expect(c.Bytes()).To(Equal([]byte{1, 2, 3, 4, 5, 6, 7}))
	})

	It("returns a nil byte slice for the default value", func() {
		var c ConnectionID
		Expect(c.Bytes()).To(BeNil())
	})

	It("has a string representation", func() {
		c := ConnectionID([]byte{0xde, 0xad, 0xbe, 0xef, 0x42})
		Expect(c.String()).To(Equal("0xdeadbeef42"))
	})

	It("has a long string representation", func() {
		c := ConnectionID{0x13, 0x37, 0, 0, 0xde, 0xca, 0xfb, 0xad}
		Expect(c.String()).To(Equal("0x13370000decafbad"))
	})

	It("has a string representation for the default value", func() {
		var c ConnectionID
		Expect(c.String()).To(Equal("(empty)"))
	})
})
