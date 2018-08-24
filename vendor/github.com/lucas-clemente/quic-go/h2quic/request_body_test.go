package h2quic

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Request body", func() {
	var (
		stream *mockStream
		rb     *requestBody
	)

	BeforeEach(func() {
		stream = &mockStream{}
		stream.dataToRead.Write([]byte("foobar")) // provides data to be read
		rb = newRequestBody(stream)
	})

	It("reads from the stream", func() {
		b := make([]byte, 10)
		n, _ := stream.Read(b)
		Expect(n).To(Equal(6))
		Expect(b[0:6]).To(Equal([]byte("foobar")))
	})

	It("saves if the stream was read from", func() {
		Expect(rb.requestRead).To(BeFalse())
		rb.Read(make([]byte, 1))
		Expect(rb.requestRead).To(BeTrue())
	})

	It("doesn't close the stream when closing the request body", func() {
		Expect(stream.closed).To(BeFalse())
		err := rb.Close()
		Expect(err).ToNot(HaveOccurred())
		Expect(stream.closed).To(BeFalse())
	})
})
