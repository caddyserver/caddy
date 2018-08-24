package congestion

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

var _ = Describe("PRR sender", func() {
	var (
		prr PrrSender
	)

	BeforeEach(func() {
		prr = PrrSender{}
	})

	It("single loss results in send on every other ack", func() {
		numPacketsInFlight := protocol.ByteCount(50)
		bytesInFlight := numPacketsInFlight * protocol.DefaultTCPMSS
		sshthreshAfterLoss := numPacketsInFlight / 2
		congestionWindow := sshthreshAfterLoss * protocol.DefaultTCPMSS

		prr.OnPacketLost(bytesInFlight)
		// Ack a packet. PRR allows one packet to leave immediately.
		prr.OnPacketAcked(protocol.DefaultTCPMSS)
		bytesInFlight -= protocol.DefaultTCPMSS
		Expect(prr.CanSend(congestionWindow, bytesInFlight, sshthreshAfterLoss*protocol.DefaultTCPMSS)).To(BeTrue())
		// Send retransmission.
		prr.OnPacketSent(protocol.DefaultTCPMSS)
		// PRR shouldn't allow sending any more packets.
		Expect(prr.CanSend(congestionWindow, bytesInFlight, sshthreshAfterLoss*protocol.DefaultTCPMSS)).To(BeFalse())

		// One packet is lost, and one ack was consumed above. PRR now paces
		// transmissions through the remaining 48 acks. PRR will alternatively
		// disallow and allow a packet to be sent in response to an ack.
		for i := protocol.ByteCount(0); i < sshthreshAfterLoss-1; i++ {
			// Ack a packet. PRR shouldn't allow sending a packet in response.
			prr.OnPacketAcked(protocol.DefaultTCPMSS)
			bytesInFlight -= protocol.DefaultTCPMSS
			Expect(prr.CanSend(congestionWindow, bytesInFlight, sshthreshAfterLoss*protocol.DefaultTCPMSS)).To(BeFalse())
			// Ack another packet. PRR should now allow sending a packet in response.
			prr.OnPacketAcked(protocol.DefaultTCPMSS)
			bytesInFlight -= protocol.DefaultTCPMSS
			Expect(prr.CanSend(congestionWindow, bytesInFlight, sshthreshAfterLoss*protocol.DefaultTCPMSS)).To(BeTrue())
			// Send a packet in response.
			prr.OnPacketSent(protocol.DefaultTCPMSS)
			bytesInFlight += protocol.DefaultTCPMSS
		}

		// Since bytes_in_flight is now equal to congestion_window, PRR now maintains
		// packet conservation, allowing one packet to be sent in response to an ack.
		Expect(bytesInFlight).To(Equal(congestionWindow))
		for i := 0; i < 10; i++ {
			// Ack a packet.
			prr.OnPacketAcked(protocol.DefaultTCPMSS)
			bytesInFlight -= protocol.DefaultTCPMSS
			Expect(prr.CanSend(congestionWindow, bytesInFlight, sshthreshAfterLoss*protocol.DefaultTCPMSS)).To(BeTrue())
			// Send a packet in response, since PRR allows it.
			prr.OnPacketSent(protocol.DefaultTCPMSS)
			bytesInFlight += protocol.DefaultTCPMSS

			// Since bytes_in_flight is equal to the congestion_window,
			// PRR disallows sending.
			Expect(bytesInFlight).To(Equal(congestionWindow))
			Expect(prr.CanSend(congestionWindow, bytesInFlight, sshthreshAfterLoss*protocol.DefaultTCPMSS)).To(BeFalse())
		}

	})

	It("burst loss results in slow start", func() {
		bytesInFlight := protocol.ByteCount(20 * protocol.DefaultTCPMSS)
		const numPacketsLost = 13
		const ssthreshAfterLoss = 10
		const congestionWindow = ssthreshAfterLoss * protocol.DefaultTCPMSS

		// Lose 13 packets.
		bytesInFlight -= numPacketsLost * protocol.DefaultTCPMSS
		prr.OnPacketLost(bytesInFlight)

		// PRR-SSRB will allow the following 3 acks to send up to 2 packets.
		for i := 0; i < 3; i++ {
			prr.OnPacketAcked(protocol.DefaultTCPMSS)
			bytesInFlight -= protocol.DefaultTCPMSS
			// PRR-SSRB should allow two packets to be sent.
			for j := 0; j < 2; j++ {
				Expect(prr.CanSend(congestionWindow, bytesInFlight, ssthreshAfterLoss*protocol.DefaultTCPMSS)).To(BeTrue())
				// Send a packet in response.
				prr.OnPacketSent(protocol.DefaultTCPMSS)
				bytesInFlight += protocol.DefaultTCPMSS
			}
			// PRR should allow no more than 2 packets in response to an ack.
			Expect(prr.CanSend(congestionWindow, bytesInFlight, ssthreshAfterLoss*protocol.DefaultTCPMSS)).To(BeFalse())
		}

		// Out of SSRB mode, PRR allows one send in response to each ack.
		for i := 0; i < 10; i++ {
			prr.OnPacketAcked(protocol.DefaultTCPMSS)
			bytesInFlight -= protocol.DefaultTCPMSS
			Expect(prr.CanSend(congestionWindow, bytesInFlight, ssthreshAfterLoss*protocol.DefaultTCPMSS)).To(BeTrue())
			// Send a packet in response.
			prr.OnPacketSent(protocol.DefaultTCPMSS)
			bytesInFlight += protocol.DefaultTCPMSS
		}
	})
})
