package qerr

import (
	"io"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Quic error", func() {
	Context("QuicError", func() {
		It("has a string representation", func() {
			err := Error(DecryptionFailure, "foobar")
			Expect(err.Error()).To(Equal("DecryptionFailure: foobar"))
		})
	})

	Context("ErrorCode", func() {
		It("works as error", func() {
			var err error = DecryptionFailure
			Expect(err).To(MatchError("DecryptionFailure"))
		})
	})

	Context("TimeoutError", func() {
		It("works as timeout error", func() {
			err := Error(HandshakeTimeout, "handshake timeout")
			Expect(err.Timeout()).Should(BeTrue())
		})
	})

	Context("ToQuicError", func() {
		It("leaves QuicError unchanged", func() {
			err := Error(DecryptionFailure, "foo")
			Expect(ToQuicError(err)).To(Equal(err))
		})

		It("wraps ErrorCode properly", func() {
			var err error = DecryptionFailure
			Expect(ToQuicError(err)).To(Equal(Error(DecryptionFailure, "")))
		})

		It("changes default errors to InternalError", func() {
			Expect(ToQuicError(io.EOF)).To(Equal(Error(InternalError, "EOF")))
		})
	})
})
