package handshake

import (
	"bytes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Crypto Stream Conn", func() {
	var (
		stream *bytes.Buffer
		csc    *cryptoStreamConn
	)

	BeforeEach(func() {
		stream = &bytes.Buffer{}
		csc = newCryptoStreamConn(stream)
	})

	It("buffers writes", func() {
		_, err := csc.Write([]byte("foo"))
		Expect(err).ToNot(HaveOccurred())
		Expect(stream.Len()).To(BeZero())
		_, err = csc.Write([]byte("bar"))
		Expect(err).ToNot(HaveOccurred())
		Expect(stream.Len()).To(BeZero())

		Expect(csc.Flush()).To(Succeed())
		Expect(stream.Bytes()).To(Equal([]byte("foobar")))
	})

	It("reads from the stream", func() {
		stream.Write([]byte("foobar"))
		b := make([]byte, 6)
		n, err := csc.Read(b)
		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(6))
		Expect(b).To(Equal([]byte("foobar")))
	})
})
