package congestion

import (
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const initialCongestionWindowPackets = 10
const defaultWindowTCP = protocol.ByteCount(initialCongestionWindowPackets) * protocol.DefaultTCPMSS

type mockClock time.Time

func (c *mockClock) Now() time.Time {
	return time.Time(*c)
}

func (c *mockClock) Advance(d time.Duration) {
	*c = mockClock(time.Time(*c).Add(d))
}

const MaxCongestionWindow protocol.ByteCount = 200 * protocol.DefaultTCPMSS

var _ = Describe("Cubic Sender", func() {
	var (
		sender            SendAlgorithmWithDebugInfo
		clock             mockClock
		bytesInFlight     protocol.ByteCount
		packetNumber      protocol.PacketNumber
		ackedPacketNumber protocol.PacketNumber
		rttStats          *RTTStats
	)

	BeforeEach(func() {
		bytesInFlight = 0
		packetNumber = 1
		ackedPacketNumber = 0
		clock = mockClock{}
		rttStats = NewRTTStats()
		sender = NewCubicSender(&clock, rttStats, true /*reno*/, initialCongestionWindowPackets*protocol.DefaultTCPMSS, MaxCongestionWindow)
	})

	canSend := func() bool {
		return bytesInFlight < sender.GetCongestionWindow()
	}

	SendAvailableSendWindowLen := func(packetLength protocol.ByteCount) int {
		packetsSent := 0
		for canSend() {
			sender.OnPacketSent(clock.Now(), bytesInFlight, packetNumber, packetLength, true)
			packetNumber++
			packetsSent++
			bytesInFlight += packetLength
		}
		return packetsSent
	}

	// Normal is that TCP acks every other segment.
	AckNPackets := func(n int) {
		rttStats.UpdateRTT(60*time.Millisecond, 0, clock.Now())
		sender.MaybeExitSlowStart()
		for i := 0; i < n; i++ {
			ackedPacketNumber++
			sender.OnPacketAcked(ackedPacketNumber, protocol.DefaultTCPMSS, bytesInFlight, clock.Now())
		}
		bytesInFlight -= protocol.ByteCount(n) * protocol.DefaultTCPMSS
		clock.Advance(time.Millisecond)
	}

	LoseNPacketsLen := func(n int, packetLength protocol.ByteCount) {
		for i := 0; i < n; i++ {
			ackedPacketNumber++
			sender.OnPacketLost(ackedPacketNumber, packetLength, bytesInFlight)
		}
		bytesInFlight -= protocol.ByteCount(n) * packetLength
	}

	// Does not increment acked_packet_number_.
	LosePacket := func(number protocol.PacketNumber) {
		sender.OnPacketLost(number, protocol.DefaultTCPMSS, bytesInFlight)
		bytesInFlight -= protocol.DefaultTCPMSS
	}

	SendAvailableSendWindow := func() int { return SendAvailableSendWindowLen(protocol.DefaultTCPMSS) }
	LoseNPackets := func(n int) { LoseNPacketsLen(n, protocol.DefaultTCPMSS) }

	It("has the right values at startup", func() {
		// At startup make sure we are at the default.
		Expect(sender.GetCongestionWindow()).To(Equal(defaultWindowTCP))
		// Make sure we can send.
		Expect(sender.TimeUntilSend(0)).To(BeZero())
		Expect(canSend()).To(BeTrue())
		// And that window is un-affected.
		Expect(sender.GetCongestionWindow()).To(Equal(defaultWindowTCP))

		// Fill the send window with data, then verify that we can't send.
		SendAvailableSendWindow()
		Expect(canSend()).To(BeFalse())
	})

	It("paces", func() {
		clock.Advance(time.Hour)
		// Fill the send window with data, then verify that we can't send.
		SendAvailableSendWindow()
		AckNPackets(1)
		delay := sender.TimeUntilSend(bytesInFlight)
		Expect(delay).ToNot(BeZero())
		Expect(delay).ToNot(Equal(utils.InfDuration))
	})

	It("application limited slow start", func() {
		// Send exactly 10 packets and ensure the CWND ends at 14 packets.
		const numberOfAcks = 5
		// At startup make sure we can send.
		Expect(sender.TimeUntilSend(0)).To(BeZero())
		// Make sure we can send.
		Expect(sender.TimeUntilSend(0)).To(BeZero())

		SendAvailableSendWindow()
		for i := 0; i < numberOfAcks; i++ {
			AckNPackets(2)
		}
		bytesToSend := sender.GetCongestionWindow()
		// It's expected 2 acks will arrive when the bytes_in_flight are greater than
		// half the CWND.
		Expect(bytesToSend).To(Equal(defaultWindowTCP + protocol.DefaultTCPMSS*2*2))
	})

	It("exponential slow start", func() {
		const numberOfAcks = 20
		// At startup make sure we can send.
		Expect(sender.TimeUntilSend(0)).To(BeZero())
		Expect(sender.BandwidthEstimate()).To(BeZero())
		// Make sure we can send.
		Expect(sender.TimeUntilSend(0)).To(BeZero())

		for i := 0; i < numberOfAcks; i++ {
			// Send our full send window.
			SendAvailableSendWindow()
			AckNPackets(2)
		}
		cwnd := sender.GetCongestionWindow()
		Expect(cwnd).To(Equal(defaultWindowTCP + protocol.DefaultTCPMSS*2*numberOfAcks))
		Expect(sender.BandwidthEstimate()).To(Equal(BandwidthFromDelta(cwnd, rttStats.SmoothedRTT())))
	})

	It("slow start packet loss", func() {
		sender.SetNumEmulatedConnections(1)
		const numberOfAcks = 10
		for i := 0; i < numberOfAcks; i++ {
			// Send our full send window.
			SendAvailableSendWindow()
			AckNPackets(2)
		}
		SendAvailableSendWindow()
		expectedSendWindow := defaultWindowTCP + (protocol.DefaultTCPMSS * 2 * numberOfAcks)
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// Lose a packet to exit slow start.
		LoseNPackets(1)
		packetsInRecoveryWindow := expectedSendWindow / protocol.DefaultTCPMSS

		// We should now have fallen out of slow start with a reduced window.
		expectedSendWindow = protocol.ByteCount(float32(expectedSendWindow) * renoBeta)
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// Recovery phase. We need to ack every packet in the recovery window before
		// we exit recovery.
		numberOfPacketsInWindow := expectedSendWindow / protocol.DefaultTCPMSS
		AckNPackets(int(packetsInRecoveryWindow))
		SendAvailableSendWindow()
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// We need to ack an entire window before we increase CWND by 1.
		AckNPackets(int(numberOfPacketsInWindow) - 2)
		SendAvailableSendWindow()
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// Next ack should increase cwnd by 1.
		AckNPackets(1)
		expectedSendWindow += protocol.DefaultTCPMSS
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// Now RTO and ensure slow start gets reset.
		Expect(sender.HybridSlowStart().Started()).To(BeTrue())
		sender.OnRetransmissionTimeout(true)
		Expect(sender.HybridSlowStart().Started()).To(BeFalse())
	})

	It("slow start packet loss with large reduction", func() {
		sender.SetSlowStartLargeReduction(true)

		sender.SetNumEmulatedConnections(1)
		const numberOfAcks = 10
		for i := 0; i < numberOfAcks; i++ {
			// Send our full send window.
			SendAvailableSendWindow()
			AckNPackets(2)
		}
		SendAvailableSendWindow()
		expectedSendWindow := defaultWindowTCP + (protocol.DefaultTCPMSS * 2 * numberOfAcks)
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// Lose a packet to exit slow start. We should now have fallen out of
		// slow start with a window reduced by 1.
		LoseNPackets(1)
		expectedSendWindow -= protocol.DefaultTCPMSS
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// Lose 5 packets in recovery and verify that congestion window is reduced
		// further.
		LoseNPackets(5)
		expectedSendWindow -= 5 * protocol.DefaultTCPMSS
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		packetsInRecoveryWindow := expectedSendWindow / protocol.DefaultTCPMSS

		// Recovery phase. We need to ack every packet in the recovery window before
		// we exit recovery.
		numberOfPacketsInWindow := expectedSendWindow / protocol.DefaultTCPMSS
		AckNPackets(int(packetsInRecoveryWindow))
		SendAvailableSendWindow()
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// We need to ack the rest of the window before cwnd increases by 1.
		AckNPackets(int(numberOfPacketsInWindow - 1))
		SendAvailableSendWindow()
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// Next ack should increase cwnd by 1.
		AckNPackets(1)
		expectedSendWindow += protocol.DefaultTCPMSS
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// Now RTO and ensure slow start gets reset.
		Expect(sender.HybridSlowStart().Started()).To(BeTrue())
		sender.OnRetransmissionTimeout(true)
		Expect(sender.HybridSlowStart().Started()).To(BeFalse())
	})

	It("slow start half packet loss with large reduction", func() {
		sender.SetSlowStartLargeReduction(true)

		sender.SetNumEmulatedConnections(1)
		const numberOfAcks = 10
		for i := 0; i < numberOfAcks; i++ {
			// Send our full send window in half sized packets.
			SendAvailableSendWindowLen(protocol.DefaultTCPMSS / 2)
			AckNPackets(2)
		}
		SendAvailableSendWindowLen(protocol.DefaultTCPMSS / 2)
		expectedSendWindow := defaultWindowTCP + (protocol.DefaultTCPMSS * 2 * numberOfAcks)
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// Lose a packet to exit slow start. We should now have fallen out of
		// slow start with a window reduced by 1.
		LoseNPackets(1)
		expectedSendWindow -= protocol.DefaultTCPMSS
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// Lose 10 packets in recovery and verify that congestion window is reduced
		// by 5 packets.
		LoseNPacketsLen(10, protocol.DefaultTCPMSS/2)
		expectedSendWindow -= 5 * protocol.DefaultTCPMSS
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))
	})

	// this test doesn't work any more after introducing the pacing needed for QUIC
	PIt("no PRR when less than one packet in flight", func() {
		SendAvailableSendWindow()
		LoseNPackets(int(initialCongestionWindowPackets) - 1)
		AckNPackets(1)
		// PRR will allow 2 packets for every ack during recovery.
		Expect(SendAvailableSendWindow()).To(Equal(2))
		// Simulate abandoning all packets by supplying a bytes_in_flight of 0.
		// PRR should now allow a packet to be sent, even though prr's state
		// variables believe it has sent enough packets.
		Expect(sender.TimeUntilSend(0)).To(BeZero())
	})

	It("slow start packet loss PRR", func() {
		sender.SetNumEmulatedConnections(1)
		// Test based on the first example in RFC6937.
		// Ack 10 packets in 5 acks to raise the CWND to 20, as in the example.
		const numberOfAcks = 5
		for i := 0; i < numberOfAcks; i++ {
			// Send our full send window.
			SendAvailableSendWindow()
			AckNPackets(2)
		}
		SendAvailableSendWindow()
		expectedSendWindow := defaultWindowTCP + (protocol.DefaultTCPMSS * 2 * numberOfAcks)
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		LoseNPackets(1)

		// We should now have fallen out of slow start with a reduced window.
		sendWindowBeforeLoss := expectedSendWindow
		expectedSendWindow = protocol.ByteCount(float32(expectedSendWindow) * renoBeta)
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// Testing TCP proportional rate reduction.
		// We should send packets paced over the received acks for the remaining
		// outstanding packets. The number of packets before we exit recovery is the
		// original CWND minus the packet that has been lost and the one which
		// triggered the loss.
		remainingPacketsInRecovery := sendWindowBeforeLoss/protocol.DefaultTCPMSS - 2

		for i := protocol.ByteCount(0); i < remainingPacketsInRecovery; i++ {
			AckNPackets(1)
			SendAvailableSendWindow()
			Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))
		}

		// We need to ack another window before we increase CWND by 1.
		numberOfPacketsInWindow := expectedSendWindow / protocol.DefaultTCPMSS
		for i := protocol.ByteCount(0); i < numberOfPacketsInWindow; i++ {
			AckNPackets(1)
			Expect(SendAvailableSendWindow()).To(Equal(1))
			Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))
		}

		AckNPackets(1)
		expectedSendWindow += protocol.DefaultTCPMSS
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))
	})

	It("slow start burst packet loss PRR", func() {
		sender.SetNumEmulatedConnections(1)
		// Test based on the second example in RFC6937, though we also implement
		// forward acknowledgements, so the first two incoming acks will trigger
		// PRR immediately.
		// Ack 20 packets in 10 acks to raise the CWND to 30.
		const numberOfAcks = 10
		for i := 0; i < numberOfAcks; i++ {
			// Send our full send window.
			SendAvailableSendWindow()
			AckNPackets(2)
		}
		SendAvailableSendWindow()
		expectedSendWindow := defaultWindowTCP + (protocol.DefaultTCPMSS * 2 * numberOfAcks)
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// Lose one more than the congestion window reduction, so that after loss,
		// bytes_in_flight is lesser than the congestion window.
		sendWindowAfterLoss := protocol.ByteCount(renoBeta * float32(expectedSendWindow))
		numPacketsToLose := (expectedSendWindow-sendWindowAfterLoss)/protocol.DefaultTCPMSS + 1
		LoseNPackets(int(numPacketsToLose))
		// Immediately after the loss, ensure at least one packet can be sent.
		// Losses without subsequent acks can occur with timer based loss detection.
		Expect(sender.TimeUntilSend(bytesInFlight)).To(BeZero())
		AckNPackets(1)

		// We should now have fallen out of slow start with a reduced window.
		expectedSendWindow = protocol.ByteCount(float32(expectedSendWindow) * renoBeta)
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// Only 2 packets should be allowed to be sent, per PRR-SSRB
		Expect(SendAvailableSendWindow()).To(Equal(2))

		// Ack the next packet, which triggers another loss.
		LoseNPackets(1)
		AckNPackets(1)

		// Send 2 packets to simulate PRR-SSRB.
		Expect(SendAvailableSendWindow()).To(Equal(2))

		// Ack the next packet, which triggers another loss.
		LoseNPackets(1)
		AckNPackets(1)

		// Send 2 packets to simulate PRR-SSRB.
		Expect(SendAvailableSendWindow()).To(Equal(2))

		// Exit recovery and return to sending at the new rate.
		for i := 0; i < numberOfAcks; i++ {
			AckNPackets(1)
			Expect(SendAvailableSendWindow()).To(Equal(1))
		}
	})

	It("RTO congestion window", func() {
		Expect(sender.GetCongestionWindow()).To(Equal(defaultWindowTCP))
		Expect(sender.SlowstartThreshold()).To(Equal(MaxCongestionWindow))

		// Expect the window to decrease to the minimum once the RTO fires
		// and slow start threshold to be set to 1/2 of the CWND.
		sender.OnRetransmissionTimeout(true)
		Expect(sender.GetCongestionWindow()).To(Equal(2 * protocol.DefaultTCPMSS))
		Expect(sender.SlowstartThreshold()).To(Equal(5 * protocol.DefaultTCPMSS))
	})

	It("RTO congestion window no retransmission", func() {
		Expect(sender.GetCongestionWindow()).To(Equal(defaultWindowTCP))

		// Expect the window to remain unchanged if the RTO fires but no
		// packets are retransmitted.
		sender.OnRetransmissionTimeout(false)
		Expect(sender.GetCongestionWindow()).To(Equal(defaultWindowTCP))
	})

	It("tcp cubic reset epoch on quiescence", func() {
		const maxCongestionWindow = 50
		const maxCongestionWindowBytes = maxCongestionWindow * protocol.DefaultTCPMSS
		sender = NewCubicSender(&clock, rttStats, false, initialCongestionWindowPackets*protocol.DefaultTCPMSS, maxCongestionWindowBytes)

		numSent := SendAvailableSendWindow()

		// Make sure we fall out of slow start.
		savedCwnd := sender.GetCongestionWindow()
		LoseNPackets(1)
		Expect(savedCwnd).To(BeNumerically(">", sender.GetCongestionWindow()))

		// Ack the rest of the outstanding packets to get out of recovery.
		for i := 1; i < numSent; i++ {
			AckNPackets(1)
		}
		Expect(bytesInFlight).To(BeZero())

		// Send a new window of data and ack all; cubic growth should occur.
		savedCwnd = sender.GetCongestionWindow()
		numSent = SendAvailableSendWindow()
		for i := 0; i < numSent; i++ {
			AckNPackets(1)
		}
		Expect(savedCwnd).To(BeNumerically("<", sender.GetCongestionWindow()))
		Expect(maxCongestionWindowBytes).To(BeNumerically(">", sender.GetCongestionWindow()))
		Expect(bytesInFlight).To(BeZero())

		// Quiescent time of 100 seconds
		clock.Advance(100 * time.Second)

		// Send new window of data and ack one packet. Cubic epoch should have
		// been reset; ensure cwnd increase is not dramatic.
		savedCwnd = sender.GetCongestionWindow()
		SendAvailableSendWindow()
		AckNPackets(1)
		Expect(savedCwnd).To(BeNumerically("~", sender.GetCongestionWindow(), protocol.DefaultTCPMSS))
		Expect(maxCongestionWindowBytes).To(BeNumerically(">", sender.GetCongestionWindow()))
	})

	It("multiple losses in one window", func() {
		SendAvailableSendWindow()
		initialWindow := sender.GetCongestionWindow()
		LosePacket(ackedPacketNumber + 1)
		postLossWindow := sender.GetCongestionWindow()
		Expect(initialWindow).To(BeNumerically(">", postLossWindow))
		LosePacket(ackedPacketNumber + 3)
		Expect(sender.GetCongestionWindow()).To(Equal(postLossWindow))
		LosePacket(packetNumber - 1)
		Expect(sender.GetCongestionWindow()).To(Equal(postLossWindow))

		// Lose a later packet and ensure the window decreases.
		LosePacket(packetNumber)
		Expect(postLossWindow).To(BeNumerically(">", sender.GetCongestionWindow()))
	})

	It("2 connection congestion avoidance at end of recovery", func() {
		sender.SetNumEmulatedConnections(2)
		// Ack 10 packets in 5 acks to raise the CWND to 20.
		const numberOfAcks = 5
		for i := 0; i < numberOfAcks; i++ {
			// Send our full send window.
			SendAvailableSendWindow()
			AckNPackets(2)
		}
		SendAvailableSendWindow()
		expectedSendWindow := defaultWindowTCP + (protocol.DefaultTCPMSS * 2 * numberOfAcks)
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		LoseNPackets(1)

		// We should now have fallen out of slow start with a reduced window.
		expectedSendWindow = protocol.ByteCount(float32(expectedSendWindow) * sender.RenoBeta())
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// No congestion window growth should occur in recovery phase, i.e., until the
		// currently outstanding 20 packets are acked.
		for i := 0; i < 10; i++ {
			// Send our full send window.
			SendAvailableSendWindow()
			Expect(sender.InRecovery()).To(BeTrue())
			AckNPackets(2)
			Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))
		}
		Expect(sender.InRecovery()).To(BeFalse())

		// Out of recovery now. Congestion window should not grow for half an RTT.
		packetsInSendWindow := expectedSendWindow / protocol.DefaultTCPMSS
		SendAvailableSendWindow()
		AckNPackets(int(packetsInSendWindow/2 - 2))
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// Next ack should increase congestion window by 1MSS.
		SendAvailableSendWindow()
		AckNPackets(2)
		expectedSendWindow += protocol.DefaultTCPMSS
		packetsInSendWindow++
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// Congestion window should remain steady again for half an RTT.
		SendAvailableSendWindow()
		AckNPackets(int(packetsInSendWindow/2 - 1))
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// Next ack should cause congestion window to grow by 1MSS.
		SendAvailableSendWindow()
		AckNPackets(2)
		expectedSendWindow += protocol.DefaultTCPMSS
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))
	})

	It("1 connection congestion avoidance at end of recovery", func() {
		sender.SetNumEmulatedConnections(1)
		// Ack 10 packets in 5 acks to raise the CWND to 20.
		const numberOfAcks = 5
		for i := 0; i < numberOfAcks; i++ {
			// Send our full send window.
			SendAvailableSendWindow()
			AckNPackets(2)
		}
		SendAvailableSendWindow()
		expectedSendWindow := defaultWindowTCP + (protocol.DefaultTCPMSS * 2 * numberOfAcks)
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		LoseNPackets(1)

		// We should now have fallen out of slow start with a reduced window.
		expectedSendWindow = protocol.ByteCount(float32(expectedSendWindow) * renoBeta)
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// No congestion window growth should occur in recovery phase, i.e., until the
		// currently outstanding 20 packets are acked.
		for i := 0; i < 10; i++ {
			// Send our full send window.
			SendAvailableSendWindow()
			Expect(sender.InRecovery()).To(BeTrue())
			AckNPackets(2)
			Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))
		}
		Expect(sender.InRecovery()).To(BeFalse())

		// Out of recovery now. Congestion window should not grow during RTT.
		for i := protocol.ByteCount(0); i < expectedSendWindow/protocol.DefaultTCPMSS-2; i += 2 {
			// Send our full send window.
			SendAvailableSendWindow()
			AckNPackets(2)
			Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))
		}

		// Next ack should cause congestion window to grow by 1MSS.
		SendAvailableSendWindow()
		AckNPackets(2)
		expectedSendWindow += protocol.DefaultTCPMSS
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))
	})

	It("reset after connection migration", func() {
		Expect(sender.GetCongestionWindow()).To(Equal(defaultWindowTCP))
		Expect(sender.SlowstartThreshold()).To(Equal(MaxCongestionWindow))

		// Starts with slow start.
		sender.SetNumEmulatedConnections(1)
		const numberOfAcks = 10
		for i := 0; i < numberOfAcks; i++ {
			// Send our full send window.
			SendAvailableSendWindow()
			AckNPackets(2)
		}
		SendAvailableSendWindow()
		expectedSendWindow := defaultWindowTCP + (protocol.DefaultTCPMSS * 2 * numberOfAcks)
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// Loses a packet to exit slow start.
		LoseNPackets(1)

		// We should now have fallen out of slow start with a reduced window. Slow
		// start threshold is also updated.
		expectedSendWindow = protocol.ByteCount(float32(expectedSendWindow) * renoBeta)
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))
		Expect(sender.SlowstartThreshold()).To(Equal(expectedSendWindow))

		// Resets cwnd and slow start threshold on connection migrations.
		sender.OnConnectionMigration()
		Expect(sender.GetCongestionWindow()).To(Equal(defaultWindowTCP))
		Expect(sender.SlowstartThreshold()).To(Equal(MaxCongestionWindow))
		Expect(sender.HybridSlowStart().Started()).To(BeFalse())
	})

	It("default max cwnd", func() {
		sender = NewCubicSender(&clock, rttStats, true /*reno*/, initialCongestionWindowPackets*protocol.DefaultTCPMSS, protocol.DefaultMaxCongestionWindow)

		defaultMaxCongestionWindowPackets := protocol.DefaultMaxCongestionWindow / protocol.DefaultTCPMSS
		for i := 1; i < int(defaultMaxCongestionWindowPackets); i++ {
			sender.MaybeExitSlowStart()
			sender.OnPacketAcked(protocol.PacketNumber(i), 1350, sender.GetCongestionWindow(), clock.Now())
		}
		Expect(sender.GetCongestionWindow()).To(Equal(protocol.DefaultMaxCongestionWindow))
	})

	It("limit cwnd increase in congestion avoidance", func() {
		// Enable Cubic.
		sender = NewCubicSender(&clock, rttStats, false, initialCongestionWindowPackets*protocol.DefaultTCPMSS, MaxCongestionWindow)
		numSent := SendAvailableSendWindow()

		// Make sure we fall out of slow start.
		savedCwnd := sender.GetCongestionWindow()
		LoseNPackets(1)
		Expect(savedCwnd).To(BeNumerically(">", sender.GetCongestionWindow()))

		// Ack the rest of the outstanding packets to get out of recovery.
		for i := 1; i < numSent; i++ {
			AckNPackets(1)
		}
		Expect(bytesInFlight).To(BeZero())

		savedCwnd = sender.GetCongestionWindow()
		SendAvailableSendWindow()

		// Ack packets until the CWND increases.
		for sender.GetCongestionWindow() == savedCwnd {
			AckNPackets(1)
			SendAvailableSendWindow()
		}
		// Bytes in flight may be larger than the CWND if the CWND isn't an exact
		// multiple of the packet sizes being sent.
		Expect(bytesInFlight).To(BeNumerically(">=", sender.GetCongestionWindow()))
		savedCwnd = sender.GetCongestionWindow()

		// Advance time 2 seconds waiting for an ack.
		clock.Advance(2 * time.Second)

		// Ack two packets.  The CWND should increase by only one packet.
		AckNPackets(2)
		Expect(sender.GetCongestionWindow()).To(Equal(savedCwnd + protocol.DefaultTCPMSS))
	})
})
