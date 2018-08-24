package ackhandler

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("receivedPacketHistory", func() {
	var (
		hist *receivedPacketHistory
	)

	BeforeEach(func() {
		hist = newReceivedPacketHistory()
	})

	Context("ranges", func() {
		It("adds the first packet", func() {
			hist.ReceivedPacket(4)
			Expect(hist.ranges.Len()).To(Equal(1))
			Expect(hist.ranges.Front().Value).To(Equal(utils.PacketInterval{Start: 4, End: 4}))
		})

		It("doesn't care about duplicate packets", func() {
			hist.ReceivedPacket(4)
			Expect(hist.ranges.Len()).To(Equal(1))
			Expect(hist.ranges.Front().Value).To(Equal(utils.PacketInterval{Start: 4, End: 4}))
		})

		It("adds a few consecutive packets", func() {
			hist.ReceivedPacket(4)
			hist.ReceivedPacket(5)
			hist.ReceivedPacket(6)
			Expect(hist.ranges.Len()).To(Equal(1))
			Expect(hist.ranges.Front().Value).To(Equal(utils.PacketInterval{Start: 4, End: 6}))
		})

		It("doesn't care about a duplicate packet contained in an existing range", func() {
			hist.ReceivedPacket(4)
			hist.ReceivedPacket(5)
			hist.ReceivedPacket(6)
			hist.ReceivedPacket(5)
			Expect(hist.ranges.Len()).To(Equal(1))
			Expect(hist.ranges.Front().Value).To(Equal(utils.PacketInterval{Start: 4, End: 6}))
		})

		It("extends a range at the front", func() {
			hist.ReceivedPacket(4)
			hist.ReceivedPacket(3)
			Expect(hist.ranges.Len()).To(Equal(1))
			Expect(hist.ranges.Front().Value).To(Equal(utils.PacketInterval{Start: 3, End: 4}))
		})

		It("creates a new range when a packet is lost", func() {
			hist.ReceivedPacket(4)
			hist.ReceivedPacket(6)
			Expect(hist.ranges.Len()).To(Equal(2))
			Expect(hist.ranges.Front().Value).To(Equal(utils.PacketInterval{Start: 4, End: 4}))
			Expect(hist.ranges.Back().Value).To(Equal(utils.PacketInterval{Start: 6, End: 6}))
		})

		It("creates a new range in between two ranges", func() {
			hist.ReceivedPacket(4)
			hist.ReceivedPacket(10)
			Expect(hist.ranges.Len()).To(Equal(2))
			hist.ReceivedPacket(7)
			Expect(hist.ranges.Len()).To(Equal(3))
			Expect(hist.ranges.Front().Value).To(Equal(utils.PacketInterval{Start: 4, End: 4}))
			Expect(hist.ranges.Front().Next().Value).To(Equal(utils.PacketInterval{Start: 7, End: 7}))
			Expect(hist.ranges.Back().Value).To(Equal(utils.PacketInterval{Start: 10, End: 10}))
		})

		It("creates a new range before an existing range for a belated packet", func() {
			hist.ReceivedPacket(6)
			hist.ReceivedPacket(4)
			Expect(hist.ranges.Len()).To(Equal(2))
			Expect(hist.ranges.Front().Value).To(Equal(utils.PacketInterval{Start: 4, End: 4}))
			Expect(hist.ranges.Back().Value).To(Equal(utils.PacketInterval{Start: 6, End: 6}))
		})

		It("extends a previous range at the end", func() {
			hist.ReceivedPacket(4)
			hist.ReceivedPacket(7)
			hist.ReceivedPacket(5)
			Expect(hist.ranges.Len()).To(Equal(2))
			Expect(hist.ranges.Front().Value).To(Equal(utils.PacketInterval{Start: 4, End: 5}))
			Expect(hist.ranges.Back().Value).To(Equal(utils.PacketInterval{Start: 7, End: 7}))
		})

		It("extends a range at the front", func() {
			hist.ReceivedPacket(4)
			hist.ReceivedPacket(7)
			hist.ReceivedPacket(6)
			Expect(hist.ranges.Len()).To(Equal(2))
			Expect(hist.ranges.Front().Value).To(Equal(utils.PacketInterval{Start: 4, End: 4}))
			Expect(hist.ranges.Back().Value).To(Equal(utils.PacketInterval{Start: 6, End: 7}))
		})

		It("closes a range", func() {
			hist.ReceivedPacket(6)
			hist.ReceivedPacket(4)
			Expect(hist.ranges.Len()).To(Equal(2))
			hist.ReceivedPacket(5)
			Expect(hist.ranges.Len()).To(Equal(1))
			Expect(hist.ranges.Front().Value).To(Equal(utils.PacketInterval{Start: 4, End: 6}))
		})

		It("closes a range in the middle", func() {
			hist.ReceivedPacket(1)
			hist.ReceivedPacket(10)
			hist.ReceivedPacket(4)
			hist.ReceivedPacket(6)
			Expect(hist.ranges.Len()).To(Equal(4))
			hist.ReceivedPacket(5)
			Expect(hist.ranges.Len()).To(Equal(3))
			Expect(hist.ranges.Front().Value).To(Equal(utils.PacketInterval{Start: 1, End: 1}))
			Expect(hist.ranges.Front().Next().Value).To(Equal(utils.PacketInterval{Start: 4, End: 6}))
			Expect(hist.ranges.Back().Value).To(Equal(utils.PacketInterval{Start: 10, End: 10}))
		})
	})

	Context("deleting", func() {
		It("does nothing when the history is empty", func() {
			hist.DeleteBelow(5)
			Expect(hist.ranges.Len()).To(BeZero())
		})

		It("deletes a range", func() {
			hist.ReceivedPacket(4)
			hist.ReceivedPacket(5)
			hist.ReceivedPacket(10)
			hist.DeleteBelow(6)
			Expect(hist.ranges.Len()).To(Equal(1))
			Expect(hist.ranges.Front().Value).To(Equal(utils.PacketInterval{Start: 10, End: 10}))
		})

		It("deletes multiple ranges", func() {
			hist.ReceivedPacket(1)
			hist.ReceivedPacket(5)
			hist.ReceivedPacket(10)
			hist.DeleteBelow(8)
			Expect(hist.ranges.Len()).To(Equal(1))
			Expect(hist.ranges.Front().Value).To(Equal(utils.PacketInterval{Start: 10, End: 10}))
		})

		It("adjusts a range, if packets are delete from an existing range", func() {
			hist.ReceivedPacket(3)
			hist.ReceivedPacket(4)
			hist.ReceivedPacket(5)
			hist.ReceivedPacket(6)
			hist.ReceivedPacket(7)
			hist.DeleteBelow(5)
			Expect(hist.ranges.Len()).To(Equal(1))
			Expect(hist.ranges.Front().Value).To(Equal(utils.PacketInterval{Start: 5, End: 7}))
		})

		It("adjusts a range, if only one packet remains in the range", func() {
			hist.ReceivedPacket(4)
			hist.ReceivedPacket(5)
			hist.ReceivedPacket(10)
			hist.DeleteBelow(5)
			Expect(hist.ranges.Len()).To(Equal(2))
			Expect(hist.ranges.Front().Value).To(Equal(utils.PacketInterval{Start: 5, End: 5}))
			Expect(hist.ranges.Back().Value).To(Equal(utils.PacketInterval{Start: 10, End: 10}))
		})

		It("keeps a one-packet range, if deleting up to the packet directly below", func() {
			hist.ReceivedPacket(4)
			hist.DeleteBelow(4)
			Expect(hist.ranges.Len()).To(Equal(1))
			Expect(hist.ranges.Front().Value).To(Equal(utils.PacketInterval{Start: 4, End: 4}))
		})

		Context("DoS protection", func() {
			It("doesn't create more than MaxTrackedReceivedAckRanges ranges", func() {
				for i := protocol.PacketNumber(1); i <= protocol.MaxTrackedReceivedAckRanges; i++ {
					err := hist.ReceivedPacket(2 * i)
					Expect(err).ToNot(HaveOccurred())
				}
				err := hist.ReceivedPacket(2*protocol.MaxTrackedReceivedAckRanges + 2)
				Expect(err).To(MatchError(errTooManyOutstandingReceivedAckRanges))
			})

			It("doesn't consider already deleted ranges for MaxTrackedReceivedAckRanges", func() {
				for i := protocol.PacketNumber(1); i <= protocol.MaxTrackedReceivedAckRanges; i++ {
					err := hist.ReceivedPacket(2 * i)
					Expect(err).ToNot(HaveOccurred())
				}
				err := hist.ReceivedPacket(2*protocol.MaxTrackedReceivedAckRanges + 2)
				Expect(err).To(MatchError(errTooManyOutstandingReceivedAckRanges))
				hist.DeleteBelow(protocol.MaxTrackedReceivedAckRanges) // deletes about half of the ranges
				err = hist.ReceivedPacket(2*protocol.MaxTrackedReceivedAckRanges + 4)
				Expect(err).ToNot(HaveOccurred())
			})
		})
	})

	Context("ACK range export", func() {
		It("returns nil if there are no ranges", func() {
			Expect(hist.GetAckRanges()).To(BeNil())
		})

		It("gets a single ACK range", func() {
			hist.ReceivedPacket(4)
			hist.ReceivedPacket(5)
			ackRanges := hist.GetAckRanges()
			Expect(ackRanges).To(HaveLen(1))
			Expect(ackRanges[0]).To(Equal(wire.AckRange{Smallest: 4, Largest: 5}))
		})

		It("gets multiple ACK ranges", func() {
			hist.ReceivedPacket(4)
			hist.ReceivedPacket(5)
			hist.ReceivedPacket(6)
			hist.ReceivedPacket(1)
			hist.ReceivedPacket(11)
			hist.ReceivedPacket(10)
			hist.ReceivedPacket(2)
			ackRanges := hist.GetAckRanges()
			Expect(ackRanges).To(HaveLen(3))
			Expect(ackRanges[0]).To(Equal(wire.AckRange{Smallest: 10, Largest: 11}))
			Expect(ackRanges[1]).To(Equal(wire.AckRange{Smallest: 4, Largest: 6}))
			Expect(ackRanges[2]).To(Equal(wire.AckRange{Smallest: 1, Largest: 2}))
		})
	})

	Context("Getting the highest ACK range", func() {
		It("returns the zero value if there are no ranges", func() {
			Expect(hist.GetHighestAckRange()).To(BeZero())
		})

		It("gets a single ACK range", func() {
			hist.ReceivedPacket(4)
			hist.ReceivedPacket(5)
			Expect(hist.GetHighestAckRange()).To(Equal(wire.AckRange{Smallest: 4, Largest: 5}))
		})

		It("gets the highest of multiple ACK ranges", func() {
			hist.ReceivedPacket(3)
			hist.ReceivedPacket(6)
			hist.ReceivedPacket(7)
			Expect(hist.GetHighestAckRange()).To(Equal(wire.AckRange{Smallest: 6, Largest: 7}))
		})
	})
})
