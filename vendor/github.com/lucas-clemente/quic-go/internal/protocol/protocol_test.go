package protocol

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Protocol", func() {
	Context("Long Header Packet Types", func() {
		It("has the correct string representation", func() {
			Expect(PacketTypeInitial.String()).To(Equal("Initial"))
			Expect(PacketTypeRetry.String()).To(Equal("Retry"))
			Expect(PacketTypeHandshake.String()).To(Equal("Handshake"))
			Expect(PacketType0RTT.String()).To(Equal("0-RTT Protected"))
			Expect(PacketType(10).String()).To(Equal("unknown packet type: 10"))
		})
	})
})
