package ackhandler

import (
	"errors"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("SentPacketHistory", func() {
	var hist *sentPacketHistory

	expectInHistory := func(packetNumbers []protocol.PacketNumber) {
		ExpectWithOffset(1, hist.packetMap).To(HaveLen(len(packetNumbers)))
		ExpectWithOffset(1, hist.packetList.Len()).To(Equal(len(packetNumbers)))
		i := 0
		hist.Iterate(func(p *Packet) (bool, error) {
			pn := packetNumbers[i]
			ExpectWithOffset(1, p.PacketNumber).To(Equal(pn))
			ExpectWithOffset(1, hist.packetMap[pn].Value.PacketNumber).To(Equal(pn))
			i++
			return true, nil
		})
	}

	BeforeEach(func() {
		hist = newSentPacketHistory()
	})

	It("saves sent packets", func() {
		hist.SentPacket(&Packet{PacketNumber: 1})
		hist.SentPacket(&Packet{PacketNumber: 3})
		hist.SentPacket(&Packet{PacketNumber: 4})
		expectInHistory([]protocol.PacketNumber{1, 3, 4})
	})

	It("gets the length", func() {
		hist.SentPacket(&Packet{PacketNumber: 1})
		hist.SentPacket(&Packet{PacketNumber: 10})
		Expect(hist.Len()).To(Equal(2))
	})

	Context("getting the first outstanding packet", func() {
		It("gets nil, if there are no packets", func() {
			Expect(hist.FirstOutstanding()).To(BeNil())
		})

		It("gets the first outstanding packet", func() {
			hist.SentPacket(&Packet{PacketNumber: 2})
			hist.SentPacket(&Packet{PacketNumber: 3})
			front := hist.FirstOutstanding()
			Expect(front).ToNot(BeNil())
			Expect(front.PacketNumber).To(Equal(protocol.PacketNumber(2)))
		})

		It("gets the second packet if the first one is retransmitted", func() {
			hist.SentPacket(&Packet{PacketNumber: 1, canBeRetransmitted: true})
			hist.SentPacket(&Packet{PacketNumber: 3, canBeRetransmitted: true})
			hist.SentPacket(&Packet{PacketNumber: 4, canBeRetransmitted: true})
			front := hist.FirstOutstanding()
			Expect(front).ToNot(BeNil())
			Expect(front.PacketNumber).To(Equal(protocol.PacketNumber(1)))
			// Queue the first packet for retransmission.
			// The first outstanding packet should now be 3.
			err := hist.MarkCannotBeRetransmitted(1)
			Expect(err).ToNot(HaveOccurred())
			front = hist.FirstOutstanding()
			Expect(front).ToNot(BeNil())
			Expect(front.PacketNumber).To(Equal(protocol.PacketNumber(3)))
		})

		It("gets the third packet if the first two are retransmitted", func() {
			hist.SentPacket(&Packet{PacketNumber: 1, canBeRetransmitted: true})
			hist.SentPacket(&Packet{PacketNumber: 3, canBeRetransmitted: true})
			hist.SentPacket(&Packet{PacketNumber: 4, canBeRetransmitted: true})
			front := hist.FirstOutstanding()
			Expect(front).ToNot(BeNil())
			Expect(front.PacketNumber).To(Equal(protocol.PacketNumber(1)))
			// Queue the second packet for retransmission.
			// The first outstanding packet should still be 3.
			err := hist.MarkCannotBeRetransmitted(3)
			Expect(err).ToNot(HaveOccurred())
			front = hist.FirstOutstanding()
			Expect(front).ToNot(BeNil())
			Expect(front.PacketNumber).To(Equal(protocol.PacketNumber(1)))
			// Queue the first packet for retransmission.
			// The first outstanding packet should still be 4.
			err = hist.MarkCannotBeRetransmitted(1)
			Expect(err).ToNot(HaveOccurred())
			front = hist.FirstOutstanding()
			Expect(front).ToNot(BeNil())
			Expect(front.PacketNumber).To(Equal(protocol.PacketNumber(4)))
		})
	})

	It("gets a packet by packet number", func() {
		p := &Packet{PacketNumber: 2}
		hist.SentPacket(p)
		Expect(hist.GetPacket(2)).To(Equal(p))
	})

	It("returns nil if the packet doesn't exist", func() {
		Expect(hist.GetPacket(1337)).To(BeNil())
	})

	It("removes packets", func() {
		hist.SentPacket(&Packet{PacketNumber: 1})
		hist.SentPacket(&Packet{PacketNumber: 4})
		hist.SentPacket(&Packet{PacketNumber: 8})
		err := hist.Remove(4)
		Expect(err).ToNot(HaveOccurred())
		expectInHistory([]protocol.PacketNumber{1, 8})
	})

	It("errors when trying to remove a non existing packet", func() {
		hist.SentPacket(&Packet{PacketNumber: 1})
		err := hist.Remove(2)
		Expect(err).To(MatchError("packet 2 not found in sent packet history"))
	})

	Context("iterating", func() {
		BeforeEach(func() {
			hist.SentPacket(&Packet{PacketNumber: 10})
			hist.SentPacket(&Packet{PacketNumber: 14})
			hist.SentPacket(&Packet{PacketNumber: 18})
		})

		It("iterates over all packets", func() {
			var iterations []protocol.PacketNumber
			err := hist.Iterate(func(p *Packet) (bool, error) {
				iterations = append(iterations, p.PacketNumber)
				return true, nil
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(iterations).To(Equal([]protocol.PacketNumber{10, 14, 18}))
		})

		It("stops iterating", func() {
			var iterations []protocol.PacketNumber
			err := hist.Iterate(func(p *Packet) (bool, error) {
				iterations = append(iterations, p.PacketNumber)
				return p.PacketNumber != 14, nil
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(iterations).To(Equal([]protocol.PacketNumber{10, 14}))
		})

		It("returns the error", func() {
			testErr := errors.New("test error")
			var iterations []protocol.PacketNumber
			err := hist.Iterate(func(p *Packet) (bool, error) {
				iterations = append(iterations, p.PacketNumber)
				if p.PacketNumber == 14 {
					return false, testErr
				}
				return true, nil
			})
			Expect(err).To(MatchError(testErr))
			Expect(iterations).To(Equal([]protocol.PacketNumber{10, 14}))
		})
	})

	Context("retransmissions", func() {
		BeforeEach(func() {
			for i := protocol.PacketNumber(1); i <= 5; i++ {
				hist.SentPacket(&Packet{PacketNumber: i})
			}
		})

		It("errors if the packet doesn't exist", func() {
			err := hist.MarkCannotBeRetransmitted(100)
			Expect(err).To(MatchError("sent packet history: packet 100 not found"))
		})

		It("adds a sent packets as a retransmission", func() {
			hist.SentPacketsAsRetransmission([]*Packet{{PacketNumber: 13}}, 2)
			expectInHistory([]protocol.PacketNumber{1, 2, 3, 4, 5, 13})
			Expect(hist.GetPacket(13).isRetransmission).To(BeTrue())
			Expect(hist.GetPacket(13).retransmissionOf).To(Equal(protocol.PacketNumber(2)))
			Expect(hist.GetPacket(2).retransmittedAs).To(Equal([]protocol.PacketNumber{13}))
		})

		It("adds multiple packets sent as a retransmission", func() {
			hist.SentPacketsAsRetransmission([]*Packet{{PacketNumber: 13}, {PacketNumber: 15}}, 2)
			expectInHistory([]protocol.PacketNumber{1, 2, 3, 4, 5, 13, 15})
			Expect(hist.GetPacket(13).isRetransmission).To(BeTrue())
			Expect(hist.GetPacket(13).retransmissionOf).To(Equal(protocol.PacketNumber(2)))
			Expect(hist.GetPacket(15).retransmissionOf).To(Equal(protocol.PacketNumber(2)))
			Expect(hist.GetPacket(2).retransmittedAs).To(Equal([]protocol.PacketNumber{13, 15}))
		})

		It("adds a packet as a normal packet if the retransmitted packet doesn't exist", func() {
			hist.SentPacketsAsRetransmission([]*Packet{{PacketNumber: 13}}, 7)
			expectInHistory([]protocol.PacketNumber{1, 2, 3, 4, 5, 13})
			Expect(hist.GetPacket(13).isRetransmission).To(BeFalse())
			Expect(hist.GetPacket(13).retransmissionOf).To(BeZero())
		})
	})

	Context("outstanding packets", func() {
		It("says if it has outstanding handshake packets", func() {
			Expect(hist.HasOutstandingHandshakePackets()).To(BeFalse())
			hist.SentPacket(&Packet{
				EncryptionLevel:    protocol.EncryptionUnencrypted,
				canBeRetransmitted: true,
			})
			Expect(hist.HasOutstandingHandshakePackets()).To(BeTrue())
		})

		It("says if it has outstanding packets", func() {
			Expect(hist.HasOutstandingHandshakePackets()).To(BeFalse())
			Expect(hist.HasOutstandingPackets()).To(BeFalse())
			hist.SentPacket(&Packet{
				EncryptionLevel:    protocol.EncryptionForwardSecure,
				canBeRetransmitted: true,
			})
			Expect(hist.HasOutstandingHandshakePackets()).To(BeFalse())
			Expect(hist.HasOutstandingPackets()).To(BeTrue())
		})

		It("doesn't consider non-retransmittable packets as outstanding", func() {
			hist.SentPacket(&Packet{
				EncryptionLevel: protocol.EncryptionUnencrypted,
			})
			Expect(hist.HasOutstandingHandshakePackets()).To(BeFalse())
			Expect(hist.HasOutstandingPackets()).To(BeFalse())
		})

		It("accounts for deleted handshake packets", func() {
			hist.SentPacket(&Packet{
				PacketNumber:       5,
				EncryptionLevel:    protocol.EncryptionSecure,
				canBeRetransmitted: true,
			})
			Expect(hist.HasOutstandingHandshakePackets()).To(BeTrue())
			err := hist.Remove(5)
			Expect(err).ToNot(HaveOccurred())
			Expect(hist.HasOutstandingHandshakePackets()).To(BeFalse())
		})

		It("accounts for deleted packets", func() {
			hist.SentPacket(&Packet{
				PacketNumber:       10,
				EncryptionLevel:    protocol.EncryptionForwardSecure,
				canBeRetransmitted: true,
			})
			Expect(hist.HasOutstandingPackets()).To(BeTrue())
			err := hist.Remove(10)
			Expect(err).ToNot(HaveOccurred())
			Expect(hist.HasOutstandingPackets()).To(BeFalse())
		})

		It("doesn't count handshake packets marked as non-retransmittable", func() {
			hist.SentPacket(&Packet{
				PacketNumber:       5,
				EncryptionLevel:    protocol.EncryptionUnencrypted,
				canBeRetransmitted: true,
			})
			Expect(hist.HasOutstandingHandshakePackets()).To(BeTrue())
			err := hist.MarkCannotBeRetransmitted(5)
			Expect(err).ToNot(HaveOccurred())
			Expect(hist.HasOutstandingHandshakePackets()).To(BeFalse())
		})

		It("doesn't count packets marked as non-retransmittable", func() {
			hist.SentPacket(&Packet{
				PacketNumber:       10,
				EncryptionLevel:    protocol.EncryptionForwardSecure,
				canBeRetransmitted: true,
			})
			Expect(hist.HasOutstandingPackets()).To(BeTrue())
			err := hist.MarkCannotBeRetransmitted(10)
			Expect(err).ToNot(HaveOccurred())
			Expect(hist.HasOutstandingPackets()).To(BeFalse())
		})

		It("counts the number of packets", func() {
			hist.SentPacket(&Packet{
				PacketNumber:       10,
				EncryptionLevel:    protocol.EncryptionForwardSecure,
				canBeRetransmitted: true,
			})
			hist.SentPacket(&Packet{
				PacketNumber:       11,
				EncryptionLevel:    protocol.EncryptionForwardSecure,
				canBeRetransmitted: true,
			})
			err := hist.Remove(11)
			Expect(err).ToNot(HaveOccurred())
			Expect(hist.HasOutstandingPackets()).To(BeTrue())
			err = hist.Remove(10)
			Expect(err).ToNot(HaveOccurred())
			Expect(hist.HasOutstandingPackets()).To(BeFalse())
		})
	})
})
