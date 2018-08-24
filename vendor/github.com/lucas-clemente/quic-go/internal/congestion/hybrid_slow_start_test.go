package congestion

import (
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Hybrid slow start", func() {
	var (
		slowStart HybridSlowStart
	)

	BeforeEach(func() {
		slowStart = HybridSlowStart{}
	})

	It("works in a simple case", func() {
		packetNumber := protocol.PacketNumber(1)
		endPacketNumber := protocol.PacketNumber(3)
		slowStart.StartReceiveRound(endPacketNumber)

		packetNumber++
		Expect(slowStart.IsEndOfRound(packetNumber)).To(BeFalse())

		// Test duplicates.
		Expect(slowStart.IsEndOfRound(packetNumber)).To(BeFalse())

		packetNumber++
		Expect(slowStart.IsEndOfRound(packetNumber)).To(BeFalse())
		packetNumber++
		Expect(slowStart.IsEndOfRound(packetNumber)).To(BeTrue())

		// Test without a new registered end_packet_number;
		packetNumber++
		Expect(slowStart.IsEndOfRound(packetNumber)).To(BeTrue())

		endPacketNumber = 20
		slowStart.StartReceiveRound(endPacketNumber)
		for packetNumber < endPacketNumber {
			packetNumber++
			Expect(slowStart.IsEndOfRound(packetNumber)).To(BeFalse())
		}
		packetNumber++
		Expect(slowStart.IsEndOfRound(packetNumber)).To(BeTrue())
	})

	It("works with delay", func() {
		rtt := 60 * time.Millisecond
		// We expect to detect the increase at +1/8 of the RTT; hence at a typical
		// RTT of 60ms the detection will happen at 67.5 ms.
		const hybridStartMinSamples = 8 // Number of acks required to trigger.

		endPacketNumber := protocol.PacketNumber(1)
		endPacketNumber++
		slowStart.StartReceiveRound(endPacketNumber)

		// Will not trigger since our lowest RTT in our burst is the same as the long
		// term RTT provided.
		for n := 0; n < hybridStartMinSamples; n++ {
			Expect(slowStart.ShouldExitSlowStart(rtt+time.Duration(n)*time.Millisecond, rtt, 100)).To(BeFalse())
		}
		endPacketNumber++
		slowStart.StartReceiveRound(endPacketNumber)
		for n := 1; n < hybridStartMinSamples; n++ {
			Expect(slowStart.ShouldExitSlowStart(rtt+(time.Duration(n)+10)*time.Millisecond, rtt, 100)).To(BeFalse())
		}
		// Expect to trigger since all packets in this burst was above the long term
		// RTT provided.
		Expect(slowStart.ShouldExitSlowStart(rtt+10*time.Millisecond, rtt, 100)).To(BeTrue())
	})

})
