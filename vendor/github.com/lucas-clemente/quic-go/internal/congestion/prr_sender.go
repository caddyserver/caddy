package congestion

import (
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

// PrrSender implements the Proportional Rate Reduction (PRR) per RFC 6937
type PrrSender struct {
	bytesSentSinceLoss      protocol.ByteCount
	bytesDeliveredSinceLoss protocol.ByteCount
	ackCountSinceLoss       protocol.ByteCount
	bytesInFlightBeforeLoss protocol.ByteCount
}

// OnPacketSent should be called after a packet was sent
func (p *PrrSender) OnPacketSent(sentBytes protocol.ByteCount) {
	p.bytesSentSinceLoss += sentBytes
}

// OnPacketLost should be called on the first loss that triggers a recovery
// period and all other methods in this class should only be called when in
// recovery.
func (p *PrrSender) OnPacketLost(bytesInFlight protocol.ByteCount) {
	p.bytesSentSinceLoss = 0
	p.bytesInFlightBeforeLoss = bytesInFlight
	p.bytesDeliveredSinceLoss = 0
	p.ackCountSinceLoss = 0
}

// OnPacketAcked should be called after a packet was acked
func (p *PrrSender) OnPacketAcked(ackedBytes protocol.ByteCount) {
	p.bytesDeliveredSinceLoss += ackedBytes
	p.ackCountSinceLoss++
}

// TimeUntilSend calculates the time until a packet can be sent
func (p *PrrSender) TimeUntilSend(congestionWindow, bytesInFlight, slowstartThreshold protocol.ByteCount) time.Duration {
	// Return QuicTime::Zero In order to ensure limited transmit always works.
	if p.bytesSentSinceLoss == 0 || bytesInFlight < protocol.DefaultTCPMSS {
		return 0
	}
	if congestionWindow > bytesInFlight {
		// During PRR-SSRB, limit outgoing packets to 1 extra MSS per ack, instead
		// of sending the entire available window. This prevents burst retransmits
		// when more packets are lost than the CWND reduction.
		//   limit = MAX(prr_delivered - prr_out, DeliveredData) + MSS
		if p.bytesDeliveredSinceLoss+p.ackCountSinceLoss*protocol.DefaultTCPMSS <= p.bytesSentSinceLoss {
			return utils.InfDuration
		}
		return 0
	}
	// Implement Proportional Rate Reduction (RFC6937).
	// Checks a simplified version of the PRR formula that doesn't use division:
	// AvailableSendWindow =
	//   CEIL(prr_delivered * ssthresh / BytesInFlightAtLoss) - prr_sent
	if p.bytesDeliveredSinceLoss*slowstartThreshold > p.bytesSentSinceLoss*p.bytesInFlightBeforeLoss {
		return 0
	}
	return utils.InfDuration
}
