package congestion

import (
	"math"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const numConnections uint32 = 2
const nConnectionBeta float32 = (float32(numConnections) - 1 + beta) / float32(numConnections)
const nConnectionBetaLastMax float32 = (float32(numConnections) - 1 + betaLastMax) / float32(numConnections)
const nConnectionAlpha float32 = 3 * float32(numConnections) * float32(numConnections) * (1 - nConnectionBeta) / (1 + nConnectionBeta)
const maxCubicTimeInterval = 30 * time.Millisecond

var _ = Describe("Cubic", func() {
	var (
		clock mockClock
		cubic *Cubic
	)

	BeforeEach(func() {
		clock = mockClock{}
		cubic = NewCubic(&clock)
	})

	renoCwnd := func(currentCwnd protocol.ByteCount) protocol.ByteCount {
		return currentCwnd + protocol.ByteCount(float32(protocol.DefaultTCPMSS)*nConnectionAlpha*float32(protocol.DefaultTCPMSS)/float32(currentCwnd))
	}

	cubicConvexCwnd := func(initialCwnd protocol.ByteCount, rtt, elapsedTime time.Duration) protocol.ByteCount {
		offset := protocol.ByteCount((elapsedTime+rtt)/time.Microsecond) << 10 / 1000000
		deltaCongestionWindow := 410 * offset * offset * offset * protocol.DefaultTCPMSS >> 40
		return initialCwnd + deltaCongestionWindow
	}

	It("works above origin (with tighter bounds)", func() {
		// Convex growth.
		const rttMin = 100 * time.Millisecond
		const rttMinS = float32(rttMin/time.Millisecond) / 1000.0
		currentCwnd := 10 * protocol.DefaultTCPMSS
		initialCwnd := currentCwnd

		clock.Advance(time.Millisecond)
		initialTime := clock.Now()
		expectedFirstCwnd := renoCwnd(currentCwnd)
		currentCwnd = cubic.CongestionWindowAfterAck(protocol.DefaultTCPMSS, currentCwnd, rttMin, initialTime)
		Expect(expectedFirstCwnd).To(Equal(currentCwnd))

		// Normal TCP phase.
		// The maximum number of expected reno RTTs can be calculated by
		// finding the point where the cubic curve and the reno curve meet.
		maxRenoRtts := int(math.Sqrt(float64(nConnectionAlpha/(0.4*rttMinS*rttMinS*rttMinS))) - 2)
		for i := 0; i < maxRenoRtts; i++ {
			// Alternatively, we expect it to increase by one, every time we
			// receive current_cwnd/Alpha acks back.  (This is another way of
			// saying we expect cwnd to increase by approximately Alpha once
			// we receive current_cwnd number ofacks back).
			numAcksThisEpoch := int(float32(currentCwnd/protocol.DefaultTCPMSS) / nConnectionAlpha)

			initialCwndThisEpoch := currentCwnd
			for n := 0; n < numAcksThisEpoch; n++ {
				// Call once per ACK.
				expectedNextCwnd := renoCwnd(currentCwnd)
				currentCwnd = cubic.CongestionWindowAfterAck(protocol.DefaultTCPMSS, currentCwnd, rttMin, clock.Now())
				Expect(currentCwnd).To(Equal(expectedNextCwnd))
			}
			// Our byte-wise Reno implementation is an estimate.  We expect
			// the cwnd to increase by approximately one MSS every
			// cwnd/kDefaultTCPMSS/Alpha acks, but it may be off by as much as
			// half a packet for smaller values of current_cwnd.
			cwndChangeThisEpoch := currentCwnd - initialCwndThisEpoch
			Expect(cwndChangeThisEpoch).To(BeNumerically("~", protocol.DefaultTCPMSS, protocol.DefaultTCPMSS/2))
			clock.Advance(100 * time.Millisecond)
		}

		for i := 0; i < 54; i++ {
			maxAcksThisEpoch := currentCwnd / protocol.DefaultTCPMSS
			interval := time.Duration(100*1000/maxAcksThisEpoch) * time.Microsecond
			for n := 0; n < int(maxAcksThisEpoch); n++ {
				clock.Advance(interval)
				currentCwnd = cubic.CongestionWindowAfterAck(protocol.DefaultTCPMSS, currentCwnd, rttMin, clock.Now())
				expectedCwnd := cubicConvexCwnd(initialCwnd, rttMin, clock.Now().Sub(initialTime))
				// If we allow per-ack updates, every update is a small cubic update.
				Expect(currentCwnd).To(Equal(expectedCwnd))
			}
		}
		expectedCwnd := cubicConvexCwnd(initialCwnd, rttMin, clock.Now().Sub(initialTime))
		currentCwnd = cubic.CongestionWindowAfterAck(protocol.DefaultTCPMSS, currentCwnd, rttMin, clock.Now())
		Expect(currentCwnd).To(Equal(expectedCwnd))
	})

	It("works above the origin with fine grained cubing", func() {
		// Start the test with an artificially large cwnd to prevent Reno
		// from over-taking cubic.
		currentCwnd := 1000 * protocol.DefaultTCPMSS
		initialCwnd := currentCwnd
		rttMin := 100 * time.Millisecond
		clock.Advance(time.Millisecond)
		initialTime := clock.Now()

		currentCwnd = cubic.CongestionWindowAfterAck(protocol.DefaultTCPMSS, currentCwnd, rttMin, clock.Now())
		clock.Advance(600 * time.Millisecond)
		currentCwnd = cubic.CongestionWindowAfterAck(protocol.DefaultTCPMSS, currentCwnd, rttMin, clock.Now())

		// We expect the algorithm to perform only non-zero, fine-grained cubic
		// increases on every ack in this case.
		for i := 0; i < 100; i++ {
			clock.Advance(10 * time.Millisecond)
			expectedCwnd := cubicConvexCwnd(initialCwnd, rttMin, clock.Now().Sub(initialTime))
			nextCwnd := cubic.CongestionWindowAfterAck(protocol.DefaultTCPMSS, currentCwnd, rttMin, clock.Now())
			// Make sure we are performing cubic increases.
			Expect(nextCwnd).To(Equal(expectedCwnd))
			// Make sure that these are non-zero, less-than-packet sized increases.
			Expect(nextCwnd).To(BeNumerically(">", currentCwnd))
			cwndDelta := nextCwnd - currentCwnd
			Expect(protocol.DefaultTCPMSS / 10).To(BeNumerically(">", cwndDelta))
			currentCwnd = nextCwnd
		}
	})

	It("handles per ack updates", func() {
		// Start the test with a large cwnd and RTT, to force the first
		// increase to be a cubic increase.
		initialCwndPackets := 150
		currentCwnd := protocol.ByteCount(initialCwndPackets) * protocol.DefaultTCPMSS
		rttMin := 350 * time.Millisecond

		// Initialize the epoch
		clock.Advance(time.Millisecond)
		// Keep track of the growth of the reno-equivalent cwnd.
		rCwnd := renoCwnd(currentCwnd)
		currentCwnd = cubic.CongestionWindowAfterAck(protocol.DefaultTCPMSS, currentCwnd, rttMin, clock.Now())
		initialCwnd := currentCwnd

		// Simulate the return of cwnd packets in less than
		// MaxCubicInterval() time.
		maxAcks := int(float32(initialCwndPackets) / nConnectionAlpha)
		interval := maxCubicTimeInterval / time.Duration(maxAcks+1)

		// In this scenario, the first increase is dictated by the cubic
		// equation, but it is less than one byte, so the cwnd doesn't
		// change.  Normally, without per-ack increases, any cwnd plateau
		// will cause the cwnd to be pinned for MaxCubicTimeInterval().  If
		// we enable per-ack updates, the cwnd will continue to grow,
		// regardless of the temporary plateau.
		clock.Advance(interval)
		rCwnd = renoCwnd(rCwnd)
		Expect(cubic.CongestionWindowAfterAck(protocol.DefaultTCPMSS, currentCwnd, rttMin, clock.Now())).To(Equal(currentCwnd))
		for i := 1; i < maxAcks; i++ {
			clock.Advance(interval)
			nextCwnd := cubic.CongestionWindowAfterAck(protocol.DefaultTCPMSS, currentCwnd, rttMin, clock.Now())
			rCwnd = renoCwnd(rCwnd)
			// The window shoud increase on every ack.
			Expect(nextCwnd).To(BeNumerically(">", currentCwnd))
			Expect(nextCwnd).To(Equal(rCwnd))
			currentCwnd = nextCwnd
		}

		// After all the acks are returned from the epoch, we expect the
		// cwnd to have increased by nearly one packet.  (Not exactly one
		// packet, because our byte-wise Reno algorithm is always a slight
		// under-estimation).  Without per-ack updates, the current_cwnd
		// would otherwise be unchanged.
		minimumExpectedIncrease := protocol.DefaultTCPMSS * 9 / 10
		Expect(currentCwnd).To(BeNumerically(">", initialCwnd+minimumExpectedIncrease))
	})

	It("handles loss events", func() {
		rttMin := 100 * time.Millisecond
		currentCwnd := 422 * protocol.DefaultTCPMSS
		expectedCwnd := renoCwnd(currentCwnd)
		// Initialize the state.
		clock.Advance(time.Millisecond)
		Expect(cubic.CongestionWindowAfterAck(protocol.DefaultTCPMSS, currentCwnd, rttMin, clock.Now())).To(Equal(expectedCwnd))

		// On the first loss, the last max congestion window is set to the
		// congestion window before the loss.
		preLossCwnd := currentCwnd
		Expect(cubic.lastMaxCongestionWindow).To(BeZero())
		expectedCwnd = protocol.ByteCount(float32(currentCwnd) * nConnectionBeta)
		Expect(cubic.CongestionWindowAfterPacketLoss(currentCwnd)).To(Equal(expectedCwnd))
		Expect(cubic.lastMaxCongestionWindow).To(Equal(preLossCwnd))
		currentCwnd = expectedCwnd

		// On the second loss, the current congestion window has not yet
		// reached the last max congestion window.  The last max congestion
		// window will be reduced by an additional backoff factor to allow
		// for competition.
		preLossCwnd = currentCwnd
		expectedCwnd = protocol.ByteCount(float32(currentCwnd) * nConnectionBeta)
		Expect(cubic.CongestionWindowAfterPacketLoss(currentCwnd)).To(Equal(expectedCwnd))
		currentCwnd = expectedCwnd
		Expect(preLossCwnd).To(BeNumerically(">", cubic.lastMaxCongestionWindow))
		expectedLastMax := protocol.ByteCount(float32(preLossCwnd) * nConnectionBetaLastMax)
		Expect(cubic.lastMaxCongestionWindow).To(Equal(expectedLastMax))
		Expect(expectedCwnd).To(BeNumerically("<", cubic.lastMaxCongestionWindow))
		// Simulate an increase, and check that we are below the origin.
		currentCwnd = cubic.CongestionWindowAfterAck(protocol.DefaultTCPMSS, currentCwnd, rttMin, clock.Now())
		Expect(cubic.lastMaxCongestionWindow).To(BeNumerically(">", currentCwnd))

		// On the final loss, simulate the condition where the congestion
		// window had a chance to grow nearly to the last congestion window.
		currentCwnd = cubic.lastMaxCongestionWindow - 1
		preLossCwnd = currentCwnd
		expectedCwnd = protocol.ByteCount(float32(currentCwnd) * nConnectionBeta)
		Expect(cubic.CongestionWindowAfterPacketLoss(currentCwnd)).To(Equal(expectedCwnd))
		expectedLastMax = preLossCwnd
		Expect(cubic.lastMaxCongestionWindow).To(Equal(expectedLastMax))
	})

	It("works below origin", func() {
		// Concave growth.
		rttMin := 100 * time.Millisecond
		currentCwnd := 422 * protocol.DefaultTCPMSS
		expectedCwnd := renoCwnd(currentCwnd)
		// Initialize the state.
		clock.Advance(time.Millisecond)
		Expect(cubic.CongestionWindowAfterAck(protocol.DefaultTCPMSS, currentCwnd, rttMin, clock.Now())).To(Equal(expectedCwnd))

		expectedCwnd = protocol.ByteCount(float32(currentCwnd) * nConnectionBeta)
		Expect(cubic.CongestionWindowAfterPacketLoss(currentCwnd)).To(Equal(expectedCwnd))
		currentCwnd = expectedCwnd
		// First update after loss to initialize the epoch.
		currentCwnd = cubic.CongestionWindowAfterAck(protocol.DefaultTCPMSS, currentCwnd, rttMin, clock.Now())
		// Cubic phase.
		for i := 0; i < 40; i++ {
			clock.Advance(100 * time.Millisecond)
			currentCwnd = cubic.CongestionWindowAfterAck(protocol.DefaultTCPMSS, currentCwnd, rttMin, clock.Now())
		}
		expectedCwnd = 553632
		Expect(currentCwnd).To(Equal(expectedCwnd))
	})
})
