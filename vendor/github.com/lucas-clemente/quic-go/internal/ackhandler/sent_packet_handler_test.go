package ackhandler

import (
	"time"

	"github.com/golang/mock/gomock"
	"github.com/lucas-clemente/quic-go/internal/congestion"
	"github.com/lucas-clemente/quic-go/internal/mocks"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func retransmittablePacket(p *Packet) *Packet {
	if p.EncryptionLevel == protocol.EncryptionUnspecified {
		p.EncryptionLevel = protocol.EncryptionForwardSecure
	}
	if p.Length == 0 {
		p.Length = 1
	}
	if p.SendTime.IsZero() {
		p.SendTime = time.Now()
	}
	p.Frames = []wire.Frame{&wire.PingFrame{}}
	return p
}

func nonRetransmittablePacket(p *Packet) *Packet {
	p = retransmittablePacket(p)
	p.Frames = []wire.Frame{
		&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}},
	}
	return p
}

func handshakePacket(p *Packet) *Packet {
	p = retransmittablePacket(p)
	p.EncryptionLevel = protocol.EncryptionUnencrypted
	return p
}

var _ = Describe("SentPacketHandler", func() {
	var (
		handler     *sentPacketHandler
		streamFrame wire.StreamFrame
	)

	BeforeEach(func() {
		rttStats := &congestion.RTTStats{}
		handler = NewSentPacketHandler(rttStats, utils.DefaultLogger, protocol.VersionWhatever).(*sentPacketHandler)
		handler.SetHandshakeComplete()
		streamFrame = wire.StreamFrame{
			StreamID: 5,
			Data:     []byte{0x13, 0x37},
		}
	})

	getPacket := func(pn protocol.PacketNumber) *Packet {
		if el, ok := handler.packetHistory.packetMap[pn]; ok {
			return &el.Value
		}
		return nil
	}

	losePacket := func(pn protocol.PacketNumber) {
		p := getPacket(pn)
		ExpectWithOffset(1, p).ToNot(BeNil())
		handler.queuePacketForRetransmission(p)
		if p.includedInBytesInFlight {
			p.includedInBytesInFlight = false
			handler.bytesInFlight -= p.Length
		}
		r := handler.DequeuePacketForRetransmission()
		ExpectWithOffset(1, r).ToNot(BeNil())
		ExpectWithOffset(1, r.PacketNumber).To(Equal(pn))
	}

	expectInPacketHistory := func(expected []protocol.PacketNumber) {
		ExpectWithOffset(1, handler.packetHistory.Len()).To(Equal(len(expected)))
		for _, p := range expected {
			ExpectWithOffset(1, handler.packetHistory.packetMap).To(HaveKey(p))
		}
	}

	updateRTT := func(rtt time.Duration) {
		handler.rttStats.UpdateRTT(rtt, 0, time.Now())
		ExpectWithOffset(1, handler.rttStats.SmoothedRTT()).To(Equal(rtt))
	}

	It("determines the packet number length", func() {
		handler.largestAcked = 0x1337
		Expect(handler.GetPacketNumberLen(0x1338)).To(Equal(protocol.PacketNumberLen2))
		Expect(handler.GetPacketNumberLen(0xfffffff)).To(Equal(protocol.PacketNumberLen4))
	})

	Context("registering sent packets", func() {
		It("accepts two consecutive packets", func() {
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 1}))
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 2}))
			Expect(handler.lastSentPacketNumber).To(Equal(protocol.PacketNumber(2)))
			expectInPacketHistory([]protocol.PacketNumber{1, 2})
			Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(2)))
			Expect(handler.skippedPackets).To(BeEmpty())
		})

		It("accepts packet number 0", func() {
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 0}))
			Expect(handler.lastSentPacketNumber).To(BeZero())
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 1}))
			Expect(handler.lastSentPacketNumber).To(Equal(protocol.PacketNumber(1)))
			expectInPacketHistory([]protocol.PacketNumber{0, 1})
			Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(2)))
			Expect(handler.skippedPackets).To(BeEmpty())
		})

		It("stores the sent time", func() {
			sendTime := time.Now().Add(-time.Minute)
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 1, SendTime: sendTime}))
			Expect(handler.lastSentRetransmittablePacketTime).To(Equal(sendTime))
		})

		It("stores the sent time of handshake packets", func() {
			sendTime := time.Now().Add(-time.Minute)
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 1, SendTime: sendTime, EncryptionLevel: protocol.EncryptionUnencrypted}))
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 2, SendTime: sendTime.Add(time.Hour), EncryptionLevel: protocol.EncryptionForwardSecure}))
			Expect(handler.lastSentHandshakePacketTime).To(Equal(sendTime))
		})

		It("does not store non-retransmittable packets", func() {
			handler.SentPacket(nonRetransmittablePacket(&Packet{PacketNumber: 1}))
			Expect(handler.packetHistory.Len()).To(BeZero())
			Expect(handler.lastSentRetransmittablePacketTime).To(BeZero())
			Expect(handler.bytesInFlight).To(BeZero())
		})

		Context("skipped packet numbers", func() {
			It("works with non-consecutive packet numbers", func() {
				handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 1}))
				handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 3}))
				Expect(handler.lastSentPacketNumber).To(Equal(protocol.PacketNumber(3)))
				expectInPacketHistory([]protocol.PacketNumber{1, 3})
				Expect(handler.skippedPackets).To(Equal([]protocol.PacketNumber{2}))
			})

			It("works with non-retransmittable packets", func() {
				handler.SentPacket(nonRetransmittablePacket(&Packet{PacketNumber: 1}))
				handler.SentPacket(nonRetransmittablePacket(&Packet{PacketNumber: 3}))
				Expect(handler.skippedPackets).To(Equal([]protocol.PacketNumber{2}))
			})

			It("recognizes multiple skipped packets", func() {
				handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 1}))
				handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 3}))
				handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 5}))
				Expect(handler.skippedPackets).To(Equal([]protocol.PacketNumber{2, 4}))
			})

			It("recognizes multiple consecutive skipped packets", func() {
				handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 1}))
				handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 4}))
				Expect(handler.skippedPackets).To(Equal([]protocol.PacketNumber{2, 3}))
			})

			It("limits the lengths of the skipped packet slice", func() {
				for i := protocol.PacketNumber(0); i < protocol.MaxTrackedSkippedPackets+5; i++ {
					handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 2*i + 1}))
				}
				Expect(handler.skippedPackets).To(HaveLen(protocol.MaxUndecryptablePackets))
				Expect(handler.skippedPackets[0]).To(Equal(protocol.PacketNumber(10)))
				Expect(handler.skippedPackets[protocol.MaxTrackedSkippedPackets-1]).To(Equal(protocol.PacketNumber(10 + 2*(protocol.MaxTrackedSkippedPackets-1))))
			})

			Context("garbage collection", func() {
				It("keeps all packet numbers above the LargestAcked", func() {
					handler.skippedPackets = []protocol.PacketNumber{2, 5, 8, 10}
					handler.largestAcked = 1
					handler.garbageCollectSkippedPackets()
					Expect(handler.skippedPackets).To(Equal([]protocol.PacketNumber{2, 5, 8, 10}))
				})

				It("doesn't keep packet numbers below the LargestAcked", func() {
					handler.skippedPackets = []protocol.PacketNumber{1, 5, 8, 10}
					handler.largestAcked = 5
					handler.garbageCollectSkippedPackets()
					Expect(handler.skippedPackets).To(Equal([]protocol.PacketNumber{8, 10}))
				})

				It("deletes all packet numbers if LargestAcked is sufficiently high", func() {
					handler.skippedPackets = []protocol.PacketNumber{1, 5, 10}
					handler.largestAcked = 15
					handler.garbageCollectSkippedPackets()
					Expect(handler.skippedPackets).To(BeEmpty())
				})
			})

			Context("ACK handling", func() {
				BeforeEach(func() {
					handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 10}))
					handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 12}))
				})

				It("rejects ACKs for skipped packets", func() {
					ack := &wire.AckFrame{
						AckRanges: []wire.AckRange{{Smallest: 10, Largest: 12}},
					}
					err := handler.ReceivedAck(ack, 1337, protocol.EncryptionForwardSecure, time.Now())
					Expect(err).To(MatchError("InvalidAckData: Received an ACK for a skipped packet number"))
				})

				It("accepts an ACK that correctly nacks a skipped packet", func() {
					ack := &wire.AckFrame{
						AckRanges: []wire.AckRange{
							{Smallest: 12, Largest: 12},
							{Smallest: 10, Largest: 10},
						},
					}
					err := handler.ReceivedAck(ack, 1337, protocol.EncryptionForwardSecure, time.Now())
					Expect(err).ToNot(HaveOccurred())
					Expect(handler.largestAcked).ToNot(BeZero())
				})
			})
		})
	})

	Context("ACK processing", func() {
		BeforeEach(func() {
			for i := protocol.PacketNumber(0); i < 10; i++ {
				handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: i}))
			}
			// Increase RTT, because the tests would be flaky otherwise
			updateRTT(time.Hour)
			Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(10)))
		})

		Context("ACK validation", func() {
			It("accepts ACKs sent in packet 0", func() {
				ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0, Largest: 5}}}
				err := handler.ReceivedAck(ack, 0, protocol.EncryptionForwardSecure, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.largestAcked).To(Equal(protocol.PacketNumber(5)))
			})

			It("rejects duplicate ACKs", func() {
				ack1 := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0, Largest: 3}}}
				ack2 := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0, Largest: 4}}}
				err := handler.ReceivedAck(ack1, 1337, protocol.EncryptionForwardSecure, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.largestAcked).To(Equal(protocol.PacketNumber(3)))
				// this wouldn't happen in practice
				// for testing purposes, we pretend send a different ACK frame in a duplicated packet, to be able to verify that it actually doesn't get processed
				err = handler.ReceivedAck(ack2, 1337, protocol.EncryptionForwardSecure, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.largestAcked).To(Equal(protocol.PacketNumber(3)))
			})

			It("rejects out of order ACKs", func() {
				// acks packets 0, 1, 2, 3
				ack1 := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0, Largest: 3}}}
				ack2 := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0, Largest: 4}}}
				err := handler.ReceivedAck(ack1, 1337, protocol.EncryptionForwardSecure, time.Now())
				Expect(err).ToNot(HaveOccurred())
				// this wouldn't happen in practive
				// a receiver wouldn't send an ACK for a lower largest acked in a packet sent later
				err = handler.ReceivedAck(ack2, 1337-1, protocol.EncryptionForwardSecure, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.largestAcked).To(Equal(protocol.PacketNumber(3)))
			})

			It("rejects ACKs with a too high LargestAcked packet number", func() {
				ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0, Largest: 9999}}}
				err := handler.ReceivedAck(ack, 1, protocol.EncryptionForwardSecure, time.Now())
				Expect(err).To(MatchError("InvalidAckData: Received ACK for an unsent package"))
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(10)))
			})

			It("ignores repeated ACKs", func() {
				ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 3}}}
				err := handler.ReceivedAck(ack, 1337, protocol.EncryptionForwardSecure, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(7)))
				err = handler.ReceivedAck(ack, 1337+1, protocol.EncryptionForwardSecure, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.largestAcked).To(Equal(protocol.PacketNumber(3)))
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(7)))
			})
		})

		Context("acks and nacks the right packets", func() {
			It("adjusts the LargestAcked, and adjusts the bytes in flight", func() {
				ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0, Largest: 5}}}
				err := handler.ReceivedAck(ack, 1, protocol.EncryptionForwardSecure, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.largestAcked).To(Equal(protocol.PacketNumber(5)))
				expectInPacketHistory([]protocol.PacketNumber{6, 7, 8, 9})
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(4)))
			})

			It("acks packet 0", func() {
				ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0, Largest: 0}}}
				err := handler.ReceivedAck(ack, 1, protocol.EncryptionForwardSecure, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(getPacket(0)).To(BeNil())
				expectInPacketHistory([]protocol.PacketNumber{1, 2, 3, 4, 5, 6, 7, 8, 9})
			})

			It("handles an ACK frame with one missing packet range", func() {
				ack := &wire.AckFrame{ // lose 4 and 5
					AckRanges: []wire.AckRange{
						{Smallest: 6, Largest: 9},
						{Smallest: 1, Largest: 3},
					},
				}
				err := handler.ReceivedAck(ack, 1, protocol.EncryptionForwardSecure, time.Now())
				Expect(err).ToNot(HaveOccurred())
				expectInPacketHistory([]protocol.PacketNumber{0, 4, 5})
			})

			It("does not ack packets below the LowestAcked", func() {
				ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 3, Largest: 8}}}
				err := handler.ReceivedAck(ack, 1, protocol.EncryptionForwardSecure, time.Now())
				Expect(err).ToNot(HaveOccurred())
				expectInPacketHistory([]protocol.PacketNumber{0, 1, 2, 9})
			})

			It("handles an ACK with multiple missing packet ranges", func() {
				ack := &wire.AckFrame{ // packets 2, 4 and 5, and 8 were lost
					AckRanges: []wire.AckRange{
						{Smallest: 9, Largest: 9},
						{Smallest: 6, Largest: 7},
						{Smallest: 3, Largest: 3},
						{Smallest: 1, Largest: 1},
					},
				}
				err := handler.ReceivedAck(ack, 1, protocol.EncryptionForwardSecure, time.Now())
				Expect(err).ToNot(HaveOccurred())
				expectInPacketHistory([]protocol.PacketNumber{0, 2, 4, 5, 8})
			})

			It("processes an ACK frame that would be sent after a late arrival of a packet", func() {
				ack1 := &wire.AckFrame{ // 3 lost
					AckRanges: []wire.AckRange{
						{Smallest: 4, Largest: 6},
						{Smallest: 1, Largest: 2},
					},
				}
				err := handler.ReceivedAck(ack1, 1, protocol.EncryptionForwardSecure, time.Now())
				Expect(err).ToNot(HaveOccurred())
				expectInPacketHistory([]protocol.PacketNumber{0, 3, 7, 8, 9})
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(5)))
				ack2 := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 6}}} // now ack 3
				err = handler.ReceivedAck(ack2, 2, protocol.EncryptionForwardSecure, time.Now())
				Expect(err).ToNot(HaveOccurred())
				expectInPacketHistory([]protocol.PacketNumber{0, 7, 8, 9})
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(4)))
			})

			It("processes an ACK frame that would be sent after a late arrival of a packet and another packet", func() {
				ack1 := &wire.AckFrame{
					AckRanges: []wire.AckRange{
						{Smallest: 4, Largest: 6},
						{Smallest: 0, Largest: 2},
					},
				}
				err := handler.ReceivedAck(ack1, 1, protocol.EncryptionForwardSecure, time.Now())
				Expect(err).ToNot(HaveOccurred())
				expectInPacketHistory([]protocol.PacketNumber{3, 7, 8, 9})
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(4)))
				ack2 := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 7}}}
				err = handler.ReceivedAck(ack2, 2, protocol.EncryptionForwardSecure, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(2)))
				expectInPacketHistory([]protocol.PacketNumber{8, 9})
			})

			It("processes an ACK that contains old ACK ranges", func() {
				ack1 := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 6}}}
				err := handler.ReceivedAck(ack1, 1, protocol.EncryptionForwardSecure, time.Now())
				Expect(err).ToNot(HaveOccurred())
				expectInPacketHistory([]protocol.PacketNumber{0, 7, 8, 9})
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(4)))
				ack2 := &wire.AckFrame{
					AckRanges: []wire.AckRange{
						{Smallest: 8, Largest: 8},
						{Smallest: 3, Largest: 3},
						{Smallest: 1, Largest: 1},
					},
				}
				err = handler.ReceivedAck(ack2, 2, protocol.EncryptionForwardSecure, time.Now())
				Expect(err).ToNot(HaveOccurred())
				expectInPacketHistory([]protocol.PacketNumber{0, 7, 9})
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(3)))
			})
		})

		Context("calculating RTT", func() {
			It("computes the RTT", func() {
				now := time.Now()
				// First, fake the sent times of the first, second and last packet
				getPacket(1).SendTime = now.Add(-10 * time.Minute)
				getPacket(2).SendTime = now.Add(-5 * time.Minute)
				getPacket(6).SendTime = now.Add(-1 * time.Minute)
				// Now, check that the proper times are used when calculating the deltas
				ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}}
				err := handler.ReceivedAck(ack, 1, protocol.EncryptionForwardSecure, time.Now())
				Expect(err).NotTo(HaveOccurred())
				Expect(handler.rttStats.LatestRTT()).To(BeNumerically("~", 10*time.Minute, 1*time.Second))
				ack = &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 2}}}
				err = handler.ReceivedAck(ack, 2, protocol.EncryptionForwardSecure, time.Now())
				Expect(err).NotTo(HaveOccurred())
				Expect(handler.rttStats.LatestRTT()).To(BeNumerically("~", 5*time.Minute, 1*time.Second))
				ack = &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 6}}}
				err = handler.ReceivedAck(ack, 3, protocol.EncryptionForwardSecure, time.Now())
				Expect(err).NotTo(HaveOccurred())
				Expect(handler.rttStats.LatestRTT()).To(BeNumerically("~", 1*time.Minute, 1*time.Second))
			})

			It("uses the DelayTime in the ACK frame", func() {
				now := time.Now()
				// make sure the rttStats have a min RTT, so that the delay is used
				handler.rttStats.UpdateRTT(5*time.Minute, 0, time.Now())
				getPacket(1).SendTime = now.Add(-10 * time.Minute)
				ack := &wire.AckFrame{
					AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}},
					DelayTime: 5 * time.Minute,
				}
				err := handler.ReceivedAck(ack, 1, protocol.EncryptionForwardSecure, time.Now())
				Expect(err).NotTo(HaveOccurred())
				Expect(handler.rttStats.LatestRTT()).To(BeNumerically("~", 5*time.Minute, 1*time.Second))
			})
		})

		Context("determining which ACKs we have received an ACK for", func() {
			BeforeEach(func() {
				ack1 := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 80, Largest: 100}}}
				ack2 := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 50, Largest: 200}}}
				morePackets := []*Packet{
					{PacketNumber: 13, Frames: []wire.Frame{ack1, &streamFrame}, Length: 1},
					{PacketNumber: 14, Frames: []wire.Frame{ack2, &streamFrame}, Length: 1},
					{PacketNumber: 15, Frames: []wire.Frame{&streamFrame}, Length: 1},
				}
				for _, packet := range morePackets {
					handler.SentPacket(packet)
				}
			})

			It("determines which ACK we have received an ACK for", func() {
				err := handler.ReceivedAck(&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 13, Largest: 15}}}, 1, protocol.EncryptionForwardSecure, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.GetLowestPacketNotConfirmedAcked()).To(Equal(protocol.PacketNumber(201)))
			})

			It("doesn't do anything when the acked packet didn't contain an ACK", func() {
				ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 13, Largest: 13}}}
				err := handler.ReceivedAck(ack, 1, protocol.EncryptionForwardSecure, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.GetLowestPacketNotConfirmedAcked()).To(Equal(protocol.PacketNumber(101)))
				ack = &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 15, Largest: 15}}}
				err = handler.ReceivedAck(ack, 2, protocol.EncryptionForwardSecure, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.GetLowestPacketNotConfirmedAcked()).To(Equal(protocol.PacketNumber(101)))
			})

			It("doesn't decrease the value", func() {
				err := handler.ReceivedAck(&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 14, Largest: 14}}}, 1, protocol.EncryptionForwardSecure, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.GetLowestPacketNotConfirmedAcked()).To(Equal(protocol.PacketNumber(201)))
				err = handler.ReceivedAck(&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 13, Largest: 13}}}, 2, protocol.EncryptionForwardSecure, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.GetLowestPacketNotConfirmedAcked()).To(Equal(protocol.PacketNumber(201)))
			})
		})
	})

	Context("ACK processing, for retransmitted packets", func() {
		It("sends a packet as retransmission", func() {
			// packet 5 was retransmitted as packet 6
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 5, Length: 10}))
			Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(10)))
			losePacket(5)
			Expect(handler.bytesInFlight).To(BeZero())
			handler.SentPacketsAsRetransmission([]*Packet{retransmittablePacket(&Packet{PacketNumber: 6, Length: 11})}, 5)
			Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(11)))
		})

		It("removes a packet when it is acked", func() {
			// packet 5 was retransmitted as packet 6
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 5, Length: 10}))
			losePacket(5)
			handler.SentPacketsAsRetransmission([]*Packet{retransmittablePacket(&Packet{PacketNumber: 6, Length: 11})}, 5)
			Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(11)))
			// ack 5
			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 5, Largest: 5}}}
			err := handler.ReceivedAck(ack, 1, protocol.EncryptionForwardSecure, time.Now())
			Expect(err).ToNot(HaveOccurred())
			expectInPacketHistory([]protocol.PacketNumber{6})
			Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(11)))
		})

		It("handles ACKs that ack the original packet as well as the retransmission", func() {
			// packet 5 was retransmitted as packet 7
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 5, Length: 10}))
			losePacket(5)
			handler.SentPacketsAsRetransmission([]*Packet{retransmittablePacket(&Packet{PacketNumber: 7, Length: 11})}, 5)
			// ack 5 and 7
			ack := &wire.AckFrame{
				AckRanges: []wire.AckRange{
					{Smallest: 7, Largest: 7},
					{Smallest: 5, Largest: 5},
				},
			}
			err := handler.ReceivedAck(ack, 1, protocol.EncryptionForwardSecure, time.Now())
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.packetHistory.Len()).To(BeZero())
			Expect(handler.bytesInFlight).To(BeZero())
		})
	})

	Context("Retransmission handling", func() {
		It("does not dequeue a packet if no ack has been received", func() {
			handler.SentPacket(&Packet{PacketNumber: 1})
			Expect(handler.DequeuePacketForRetransmission()).To(BeNil())
		})

		Context("STOP_WAITINGs", func() {
			It("gets a STOP_WAITING frame", func() {
				handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 1}))
				handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 2}))
				handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 3}))
				ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 3, Largest: 3}}}
				err := handler.ReceivedAck(ack, 2, protocol.EncryptionForwardSecure, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.GetStopWaitingFrame(false)).To(Equal(&wire.StopWaitingFrame{LeastUnacked: 4}))
			})

			It("gets a STOP_WAITING frame after queueing a retransmission", func() {
				handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 5}))
				handler.queuePacketForRetransmission(getPacket(5))
				Expect(handler.GetStopWaitingFrame(false)).To(Equal(&wire.StopWaitingFrame{LeastUnacked: 6}))
			})
		})
	})

	Context("congestion", func() {
		var cong *mocks.MockSendAlgorithm

		BeforeEach(func() {
			cong = mocks.NewMockSendAlgorithm(mockCtrl)
			handler.congestion = cong
		})

		It("should call OnSent", func() {
			cong.EXPECT().OnPacketSent(
				gomock.Any(),
				protocol.ByteCount(42),
				protocol.PacketNumber(1),
				protocol.ByteCount(42),
				true,
			)
			cong.EXPECT().TimeUntilSend(gomock.Any())
			p := &Packet{
				PacketNumber: 1,
				Length:       42,
				Frames:       []wire.Frame{&wire.PingFrame{}},
			}
			handler.SentPacket(p)
		})

		It("should call MaybeExitSlowStart and OnPacketAcked", func() {
			rcvTime := time.Now().Add(-5 * time.Second)
			cong.EXPECT().OnPacketSent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(3)
			cong.EXPECT().TimeUntilSend(gomock.Any()).Times(3)
			gomock.InOrder(
				cong.EXPECT().MaybeExitSlowStart(), // must be called before packets are acked
				cong.EXPECT().OnPacketAcked(protocol.PacketNumber(1), protocol.ByteCount(1), protocol.ByteCount(3), rcvTime),
				cong.EXPECT().OnPacketAcked(protocol.PacketNumber(2), protocol.ByteCount(1), protocol.ByteCount(3), rcvTime),
			)
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 1}))
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 2}))
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 3}))
			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 2}}}
			err := handler.ReceivedAck(ack, 1, protocol.EncryptionForwardSecure, rcvTime)
			Expect(err).NotTo(HaveOccurred())
		})

		It("doesn't call OnPacketLost and OnRetransmissionTimeout when queuing RTOs", func() {
			for i := protocol.PacketNumber(1); i < 3; i++ {
				cong.EXPECT().OnPacketSent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
				cong.EXPECT().TimeUntilSend(gomock.Any())
				handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: i}))
			}
			handler.OnAlarm() // TLP
			handler.OnAlarm() // TLP
			handler.OnAlarm() // RTO
		})

		It("declares all lower packets lost and call OnRetransmissionTimeout when verifying an RTO", func() {
			cong.EXPECT().OnPacketSent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(5)
			cong.EXPECT().TimeUntilSend(gomock.Any()).Times(5)
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 1, SendTime: time.Now().Add(-time.Hour)}))
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 2, SendTime: time.Now().Add(-time.Hour)}))
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 3, SendTime: time.Now().Add(-time.Hour)}))
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 4, SendTime: time.Now().Add(-time.Hour)}))
			handler.OnAlarm() // TLP
			handler.OnAlarm() // TLP
			handler.OnAlarm() // RTO
			// send one probe packet and receive an ACK for it
			rcvTime := time.Now()
			gomock.InOrder(
				cong.EXPECT().MaybeExitSlowStart(),
				cong.EXPECT().OnRetransmissionTimeout(true),
				cong.EXPECT().OnPacketAcked(protocol.PacketNumber(5), protocol.ByteCount(1), protocol.ByteCount(5), rcvTime),
				cong.EXPECT().OnPacketLost(protocol.PacketNumber(1), protocol.ByteCount(1), protocol.ByteCount(5)),
				cong.EXPECT().OnPacketLost(protocol.PacketNumber(2), protocol.ByteCount(1), protocol.ByteCount(5)),
				cong.EXPECT().OnPacketLost(protocol.PacketNumber(3), protocol.ByteCount(1), protocol.ByteCount(5)),
				cong.EXPECT().OnPacketLost(protocol.PacketNumber(4), protocol.ByteCount(1), protocol.ByteCount(5)),
			)
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 5}))
			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 5, Largest: 5}}}
			err := handler.ReceivedAck(ack, 1, protocol.EncryptionForwardSecure, rcvTime)
			Expect(err).ToNot(HaveOccurred())
		})

		It("doesn't call OnRetransmissionTimeout when a spurious RTO occurs", func() {
			cong.EXPECT().OnPacketSent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(3)
			cong.EXPECT().TimeUntilSend(gomock.Any()).Times(3)
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 1, SendTime: time.Now().Add(-time.Hour)}))
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 2, SendTime: time.Now()}))
			handler.OnAlarm() // TLP
			handler.OnAlarm() // TLP
			handler.OnAlarm() // RTO

			// send one probe packet
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 3}))
			// receive an ACK for a packet send *before* the probe packet
			// don't EXPECT any call to OnRetransmissionTimeout
			gomock.InOrder(
				cong.EXPECT().MaybeExitSlowStart(),
				cong.EXPECT().OnPacketAcked(protocol.PacketNumber(2), protocol.ByteCount(1), protocol.ByteCount(3), gomock.Any()),
				cong.EXPECT().OnPacketLost(protocol.PacketNumber(1), protocol.ByteCount(1), protocol.ByteCount(3)),
			)
			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 2, Largest: 2}}}
			err := handler.ReceivedAck(ack, 1, protocol.EncryptionForwardSecure, time.Now())
			Expect(err).ToNot(HaveOccurred())
		})

		It("doesn't call OnPacketAcked when a retransmitted packet is acked", func() {
			cong.EXPECT().OnPacketSent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(2)
			cong.EXPECT().TimeUntilSend(gomock.Any()).Times(2)
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 1, SendTime: time.Now().Add(-time.Hour)}))
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 2}))
			// lose packet 1
			gomock.InOrder(
				cong.EXPECT().MaybeExitSlowStart(),
				cong.EXPECT().OnPacketAcked(protocol.PacketNumber(2), protocol.ByteCount(1), protocol.ByteCount(2), gomock.Any()),
				cong.EXPECT().OnPacketLost(protocol.PacketNumber(1), protocol.ByteCount(1), protocol.ByteCount(2)),
			)
			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 2, Largest: 2}}}
			err := handler.ReceivedAck(ack, 1, protocol.EncryptionForwardSecure, time.Now())
			Expect(err).ToNot(HaveOccurred())
			// don't EXPECT any further calls to the congestion controller
			ack = &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 2}}}
			err = handler.ReceivedAck(ack, 2, protocol.EncryptionForwardSecure, time.Now())
			Expect(err).ToNot(HaveOccurred())
		})

		It("calls OnPacketAcked and OnPacketLost with the right bytes_in_flight value", func() {
			cong.EXPECT().OnPacketSent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(4)
			cong.EXPECT().TimeUntilSend(gomock.Any()).Times(4)
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 1, SendTime: time.Now().Add(-time.Hour)}))
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 2, SendTime: time.Now().Add(-30 * time.Minute)}))
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 3, SendTime: time.Now().Add(-30 * time.Minute)}))
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 4, SendTime: time.Now()}))
			// receive the first ACK
			gomock.InOrder(
				cong.EXPECT().MaybeExitSlowStart(),
				cong.EXPECT().OnPacketAcked(protocol.PacketNumber(2), protocol.ByteCount(1), protocol.ByteCount(4), gomock.Any()),
				cong.EXPECT().OnPacketLost(protocol.PacketNumber(1), protocol.ByteCount(1), protocol.ByteCount(4)),
			)
			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 2, Largest: 2}}}
			err := handler.ReceivedAck(ack, 1, protocol.EncryptionForwardSecure, time.Now().Add(-30*time.Minute))
			Expect(err).ToNot(HaveOccurred())
			// receive the second ACK
			gomock.InOrder(
				cong.EXPECT().MaybeExitSlowStart(),
				cong.EXPECT().OnPacketAcked(protocol.PacketNumber(4), protocol.ByteCount(1), protocol.ByteCount(2), gomock.Any()),
				cong.EXPECT().OnPacketLost(protocol.PacketNumber(3), protocol.ByteCount(1), protocol.ByteCount(2)),
			)
			ack = &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 4, Largest: 4}}}
			err = handler.ReceivedAck(ack, 2, protocol.EncryptionForwardSecure, time.Now())
			Expect(err).ToNot(HaveOccurred())
		})

		It("only allows sending of ACKs when congestion limited", func() {
			handler.bytesInFlight = 100
			cong.EXPECT().GetCongestionWindow().Return(protocol.ByteCount(200))
			Expect(handler.SendMode()).To(Equal(SendAny))
			cong.EXPECT().GetCongestionWindow().Return(protocol.ByteCount(75))
			Expect(handler.SendMode()).To(Equal(SendAck))
		})

		It("only allows sending of ACKs when we're keeping track of MaxOutstandingSentPackets packets", func() {
			cong.EXPECT().GetCongestionWindow().Return(protocol.MaxByteCount).AnyTimes()
			cong.EXPECT().TimeUntilSend(gomock.Any()).AnyTimes()
			cong.EXPECT().OnPacketSent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
			for i := protocol.PacketNumber(1); i < protocol.MaxOutstandingSentPackets; i++ {
				handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: i}))
				Expect(handler.SendMode()).To(Equal(SendAny))
			}
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: protocol.MaxOutstandingSentPackets}))
			Expect(handler.SendMode()).To(Equal(SendAck))
		})

		It("doesn't allow retransmission if congestion limited", func() {
			handler.bytesInFlight = 100
			handler.retransmissionQueue = []*Packet{{PacketNumber: 3}}
			cong.EXPECT().GetCongestionWindow().Return(protocol.ByteCount(50))
			Expect(handler.SendMode()).To(Equal(SendAck))
		})

		It("allows sending retransmissions", func() {
			cong.EXPECT().GetCongestionWindow().Return(protocol.MaxByteCount)
			handler.retransmissionQueue = []*Packet{{PacketNumber: 3}}
			Expect(handler.SendMode()).To(Equal(SendRetransmission))
		})

		It("allow retransmissions, if we're keeping track of between MaxOutstandingSentPackets and MaxTrackedSentPackets packets", func() {
			cong.EXPECT().GetCongestionWindow().Return(protocol.MaxByteCount)
			Expect(protocol.MaxOutstandingSentPackets).To(BeNumerically("<", protocol.MaxTrackedSentPackets))
			handler.retransmissionQueue = make([]*Packet, protocol.MaxOutstandingSentPackets+10)
			Expect(handler.SendMode()).To(Equal(SendRetransmission))
			handler.retransmissionQueue = make([]*Packet, protocol.MaxTrackedSentPackets)
			Expect(handler.SendMode()).To(Equal(SendNone))
		})

		It("allows RTOs, even when congestion limited", func() {
			// note that we don't EXPECT a call to GetCongestionWindow
			// that means retransmissions are sent without considering the congestion window
			handler.numRTOs = 1
			handler.retransmissionQueue = []*Packet{{PacketNumber: 3}}
			Expect(handler.SendMode()).To(Equal(SendRTO))
		})

		It("gets the pacing delay", func() {
			sendTime := time.Now().Add(-time.Minute)
			handler.bytesInFlight = 100
			cong.EXPECT().OnPacketSent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
			cong.EXPECT().TimeUntilSend(protocol.ByteCount(100)).Return(time.Hour)
			handler.SentPacket(&Packet{PacketNumber: 1, SendTime: sendTime})
			Expect(handler.TimeUntilSend()).To(Equal(sendTime.Add(time.Hour)))
		})

		It("allows sending of all RTO probe packets", func() {
			handler.numRTOs = 5
			Expect(handler.ShouldSendNumPackets()).To(Equal(5))
		})

		It("allows sending of one packet, if it should be sent immediately", func() {
			cong.EXPECT().TimeUntilSend(gomock.Any()).Return(time.Duration(0))
			Expect(handler.ShouldSendNumPackets()).To(Equal(1))
		})

		It("allows sending of multiple packets, if the pacing delay is smaller than the minimum", func() {
			pacingDelay := protocol.MinPacingDelay / 10
			cong.EXPECT().TimeUntilSend(gomock.Any()).Return(pacingDelay)
			Expect(handler.ShouldSendNumPackets()).To(Equal(10))
		})

		It("allows sending of multiple packets, if the pacing delay is smaller than the minimum, and not a fraction", func() {
			pacingDelay := protocol.MinPacingDelay * 2 / 5
			cong.EXPECT().TimeUntilSend(gomock.Any()).Return(pacingDelay)
			Expect(handler.ShouldSendNumPackets()).To(Equal(3))
		})
	})

	It("doesn't set an alarm if there are no outstanding packets", func() {
		handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 10}))
		handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 11}))
		ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 10, Largest: 11}}}
		err := handler.ReceivedAck(ack, 1, protocol.EncryptionForwardSecure, time.Now())
		Expect(err).ToNot(HaveOccurred())
		Expect(handler.GetAlarmTimeout()).To(BeZero())
	})

	It("does nothing on OnAlarm if there are no outstanding packets", func() {
		Expect(handler.OnAlarm()).To(Succeed())
		Expect(handler.SendMode()).To(Equal(SendAny))
	})

	Context("TLPs", func() {
		It("uses the RTT from RTT stats", func() {
			rtt := 2 * time.Second
			updateRTT(rtt)
			Expect(handler.computeTLPTimeout()).To(Equal(rtt * 3 / 2))
		})

		It("uses the minTLPTimeout for short RTTs", func() {
			rtt := 2 * time.Microsecond
			updateRTT(rtt)
			Expect(handler.computeTLPTimeout()).To(Equal(minTPLTimeout))
		})

		It("sets the TLP send mode until one retransmittable packet is sent", func() {
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 1, SendTime: time.Now().Add(-time.Hour)}))
			handler.OnAlarm()
			Expect(handler.SendMode()).To(Equal(SendTLP))
			// Send a non-retransmittable packet.
			// It doesn't count as a probe packet.
			handler.SentPacket(nonRetransmittablePacket(&Packet{PacketNumber: 2}))
			Expect(handler.SendMode()).To(Equal(SendTLP))
			// Send a retransmittable packet.
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 3}))
			Expect(handler.SendMode()).ToNot(Equal(SendTLP))
		})

		It("sends two TLPs, then RTOs", func() {
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 1, SendTime: time.Now().Add(-time.Hour)}))
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 2, SendTime: time.Now().Add(-time.Hour)}))
			// first TLP
			handler.OnAlarm()
			Expect(handler.SendMode()).To(Equal(SendTLP))
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 3}))
			// second TLP
			handler.OnAlarm()
			Expect(handler.SendMode()).To(Equal(SendTLP))
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 4}))
			// fire alarm a third time
			handler.OnAlarm()
			Expect(handler.SendMode()).To(Equal(SendRTO))
		})
	})

	Context("RTOs", func() {
		It("uses default RTO", func() {
			Expect(handler.computeRTOTimeout()).To(Equal(defaultRTOTimeout))
		})

		It("uses RTO from rttStats", func() {
			rtt := time.Second
			handler.rttStats.UpdateRTT(rtt, 0, time.Now())
			Expect(handler.rttStats.SmoothedRTT()).To(Equal(rtt))
			Expect(handler.rttStats.MeanDeviation()).To(Equal(rtt / 2))
			expected := rtt + rtt/2*4
			Expect(handler.computeRTOTimeout()).To(Equal(expected))
		})

		It("limits RTO min", func() {
			rtt := 3 * time.Millisecond
			updateRTT(rtt)
			Expect(handler.computeRTOTimeout()).To(Equal(minRTOTimeout))
		})

		It("limits RTO max", func() {
			updateRTT(time.Hour)
			Expect(handler.computeRTOTimeout()).To(Equal(maxRTOTimeout))
		})

		It("implements exponential backoff", func() {
			handler.rtoCount = 0
			Expect(handler.computeRTOTimeout()).To(Equal(defaultRTOTimeout))
			handler.rtoCount = 1
			Expect(handler.computeRTOTimeout()).To(Equal(2 * defaultRTOTimeout))
			handler.rtoCount = 2
			Expect(handler.computeRTOTimeout()).To(Equal(4 * defaultRTOTimeout))
		})

		It("gets two probe packets if RTO expires", func() {
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 1}))
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 2}))

			updateRTT(time.Hour)
			Expect(handler.lossTime.IsZero()).To(BeTrue())
			Expect(time.Until(handler.GetAlarmTimeout())).To(BeNumerically("~", handler.computeRTOTimeout(), time.Minute))

			handler.OnAlarm() // TLP
			handler.OnAlarm() // TLP
			handler.OnAlarm() // RTO
			p, err := handler.DequeueProbePacket()
			Expect(err).ToNot(HaveOccurred())
			Expect(p).ToNot(BeNil())
			Expect(p.PacketNumber).To(Equal(protocol.PacketNumber(1)))
			p, err = handler.DequeueProbePacket()
			Expect(err).ToNot(HaveOccurred())
			Expect(p).ToNot(BeNil())
			Expect(p.PacketNumber).To(Equal(protocol.PacketNumber(2)))
			Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(2)))

			Expect(handler.rtoCount).To(BeEquivalentTo(1))
		})

		It("doesn't delete packets transmitted as RTO from the history", func() {
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 1, SendTime: time.Now().Add(-time.Hour)}))
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 2, SendTime: time.Now().Add(-time.Hour)}))
			handler.rttStats.UpdateRTT(time.Second, 0, time.Now())
			handler.OnAlarm() // TLP
			handler.OnAlarm() // TLP
			handler.OnAlarm() // RTO
			_, err := handler.DequeueProbePacket()
			Expect(err).ToNot(HaveOccurred())
			_, err = handler.DequeueProbePacket()
			Expect(err).ToNot(HaveOccurred())
			expectInPacketHistory([]protocol.PacketNumber{1, 2})
			Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(2)))
			// Send a probe packet and receive an ACK for it.
			// This verifies the RTO.
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 3}))
			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 3, Largest: 3}}}
			err = handler.ReceivedAck(ack, 1, protocol.EncryptionForwardSecure, time.Now())
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.packetHistory.Len()).To(BeZero())
			Expect(handler.bytesInFlight).To(BeZero())
			Expect(handler.retransmissionQueue).To(BeEmpty()) // 1 and 2 were already sent as probe packets
		})

		It("allows sending of two probe packets", func() {
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 1, SendTime: time.Now().Add(-time.Hour)}))
			handler.OnAlarm()                                                   // TLP
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 2})) // send the first TLP
			handler.OnAlarm()                                                   // TLP
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 3})) // send the second TLP
			handler.OnAlarm()                                                   // RTO
			Expect(handler.SendMode()).To(Equal(SendRTO))
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 4}))
			Expect(handler.SendMode()).To(Equal(SendRTO))
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 5}))
			Expect(handler.SendMode()).ToNot(Equal(SendRTO))
		})

		It("gets packets sent before the probe packet for retransmission", func() {
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 1, SendTime: time.Now().Add(-time.Hour)}))
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 2, SendTime: time.Now().Add(-time.Hour)}))
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 3, SendTime: time.Now().Add(-time.Hour)}))
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 4, SendTime: time.Now().Add(-time.Hour)}))
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 5, SendTime: time.Now().Add(-time.Hour)}))
			handler.OnAlarm() // TLP
			handler.OnAlarm() // TLP
			handler.OnAlarm() // RTO
			_, err := handler.DequeueProbePacket()
			Expect(err).ToNot(HaveOccurred())
			_, err = handler.DequeueProbePacket()
			Expect(err).ToNot(HaveOccurred())
			expectInPacketHistory([]protocol.PacketNumber{1, 2, 3, 4, 5})
			// Send a probe packet and receive an ACK for it.
			// This verifies the RTO.
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 6}))
			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 6, Largest: 6}}}
			err = handler.ReceivedAck(ack, 1, protocol.EncryptionForwardSecure, time.Now())
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.packetHistory.Len()).To(BeZero())
			Expect(handler.bytesInFlight).To(BeZero())
			Expect(handler.retransmissionQueue).To(HaveLen(3)) // packets 3, 4, 5
		})

		It("handles ACKs for the original packet", func() {
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 5, SendTime: time.Now().Add(-time.Hour)}))
			handler.rttStats.UpdateRTT(time.Second, 0, time.Now())
			handler.OnAlarm() // TLP
			handler.OnAlarm() // TLP
			handler.OnAlarm() // RTO
			handler.SentPacketsAsRetransmission([]*Packet{retransmittablePacket(&Packet{PacketNumber: 6})}, 5)
			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 5, Largest: 5}}}
			err := handler.ReceivedAck(ack, 1, protocol.EncryptionForwardSecure, time.Now())
			Expect(err).ToNot(HaveOccurred())
			err = handler.OnAlarm()
			Expect(err).ToNot(HaveOccurred())
		})

		It("handles ACKs for the original packet", func() {
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 5, SendTime: time.Now().Add(-time.Hour)}))
			handler.rttStats.UpdateRTT(time.Second, 0, time.Now())
			err := handler.OnAlarm()
			Expect(err).ToNot(HaveOccurred())
			err = handler.OnAlarm()
			Expect(err).ToNot(HaveOccurred())
		})
	})

	Context("Delay-based loss detection", func() {
		It("immediately detects old packets as lost when receiving an ACK", func() {
			now := time.Now()
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 1, SendTime: now.Add(-time.Hour)}))
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 2, SendTime: now.Add(-time.Second)}))
			Expect(handler.lossTime.IsZero()).To(BeTrue())

			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 2, Largest: 2}}}
			err := handler.ReceivedAck(ack, 1, protocol.EncryptionForwardSecure, now)
			Expect(err).NotTo(HaveOccurred())
			Expect(handler.DequeuePacketForRetransmission()).ToNot(BeNil())
			Expect(handler.DequeuePacketForRetransmission()).To(BeNil())
			// no need to set an alarm, since packet 1 was already declared lost
			Expect(handler.lossTime.IsZero()).To(BeTrue())
			Expect(handler.bytesInFlight).To(BeZero())
		})

		It("sets the early retransmit alarm", func() {
			now := time.Now()
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 1, SendTime: now.Add(-2 * time.Second)}))
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 2, SendTime: now.Add(-2 * time.Second)}))
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 3, SendTime: now.Add(-time.Second)}))
			Expect(handler.lossTime.IsZero()).To(BeTrue())

			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 2, Largest: 2}}}
			err := handler.ReceivedAck(ack, 1, protocol.EncryptionForwardSecure, now.Add(-time.Second))
			Expect(err).NotTo(HaveOccurred())
			Expect(handler.rttStats.SmoothedRTT()).To(Equal(time.Second))

			// Packet 1 should be considered lost (1+1/8) RTTs after it was sent.
			Expect(handler.lossTime.IsZero()).To(BeFalse())
			Expect(handler.lossTime.Sub(getPacket(1).SendTime)).To(Equal(time.Second * 9 / 8))

			err = handler.OnAlarm()
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.DequeuePacketForRetransmission()).NotTo(BeNil())
			// make sure this is not an RTO: only packet 1 is retransmissted
			Expect(handler.DequeuePacketForRetransmission()).To(BeNil())
		})
	})

	Context("handshake packets", func() {
		BeforeEach(func() {
			handler.handshakeComplete = false
		})

		It("detects the handshake timeout", func() {
			now := time.Now()
			sendTime := now.Add(-time.Minute)
			lastHandshakePacketSendTime := now.Add(-30 * time.Second)
			// send handshake packets: 1, 3
			// send a forward-secure packet: 2
			handler.SentPacket(handshakePacket(&Packet{PacketNumber: 1, SendTime: sendTime}))
			handler.SentPacket(retransmittablePacket(&Packet{PacketNumber: 2, SendTime: sendTime}))
			handler.SentPacket(handshakePacket(&Packet{PacketNumber: 3, SendTime: sendTime}))

			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}}
			err := handler.ReceivedAck(ack, 1, protocol.EncryptionForwardSecure, now)
			// RTT is now 1 minute
			Expect(handler.rttStats.SmoothedRTT()).To(Equal(time.Minute))
			Expect(err).NotTo(HaveOccurred())
			Expect(handler.lossTime.IsZero()).To(BeTrue())
			Expect(handler.GetAlarmTimeout().Sub(sendTime)).To(Equal(2 * time.Minute))

			err = handler.OnAlarm()
			Expect(err).ToNot(HaveOccurred())
			p := handler.DequeuePacketForRetransmission()
			Expect(p).ToNot(BeNil())
			Expect(p.PacketNumber).To(Equal(protocol.PacketNumber(3)))
			Expect(handler.handshakeCount).To(BeEquivalentTo(1))
			handler.SentPacket(handshakePacket(&Packet{PacketNumber: 4, SendTime: lastHandshakePacketSendTime}))
			// make sure the exponential backoff is used
			Expect(handler.GetAlarmTimeout().Sub(lastHandshakePacketSendTime)).To(Equal(4 * time.Minute))
		})

		It("rejects an ACK that acks packets with a higher encryption level", func() {
			handler.SentPacket(&Packet{
				PacketNumber:    13,
				EncryptionLevel: protocol.EncryptionForwardSecure,
				Frames:          []wire.Frame{&streamFrame},
				Length:          1,
			})
			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 13, Largest: 13}}}
			err := handler.ReceivedAck(ack, 1, protocol.EncryptionSecure, time.Now())
			Expect(err).To(MatchError("Received ACK with encryption level encrypted (not forward-secure) that acks a packet 13 (encryption level forward-secure)"))
		})

		It("deletes non forward-secure packets when the handshake completes", func() {
			for i := protocol.PacketNumber(1); i <= 6; i++ {
				p := retransmittablePacket(&Packet{PacketNumber: i})
				p.EncryptionLevel = protocol.EncryptionSecure
				handler.SentPacket(p)
			}
			handler.queuePacketForRetransmission(getPacket(1))
			handler.queuePacketForRetransmission(getPacket(3))
			handler.SetHandshakeComplete()
			Expect(handler.packetHistory.Len()).To(BeZero())
			packet := handler.DequeuePacketForRetransmission()
			Expect(packet).To(BeNil())
		})
	})
})
