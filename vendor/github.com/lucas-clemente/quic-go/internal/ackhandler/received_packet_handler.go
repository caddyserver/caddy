package ackhandler

import (
	"time"

	"github.com/lucas-clemente/quic-go/internal/congestion"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type receivedPacketHandler struct {
	largestObserved             protocol.PacketNumber
	ignoreBelow                 protocol.PacketNumber
	largestObservedReceivedTime time.Time

	packetHistory *receivedPacketHistory

	ackSendDelay time.Duration
	rttStats     *congestion.RTTStats

	packetsReceivedSinceLastAck                int
	retransmittablePacketsReceivedSinceLastAck int
	ackQueued                                  bool
	ackAlarm                                   time.Time
	lastAck                                    *wire.AckFrame

	logger utils.Logger

	version protocol.VersionNumber
}

const (
	// maximum delay that can be applied to an ACK for a retransmittable packet
	ackSendDelay = 25 * time.Millisecond
	// initial maximum number of retransmittable packets received before sending an ack.
	initialRetransmittablePacketsBeforeAck = 2
	// number of retransmittable that an ACK is sent for
	retransmittablePacketsBeforeAck = 10
	// 1/5 RTT delay when doing ack decimation
	ackDecimationDelay = 1.0 / 4
	// 1/8 RTT delay when doing ack decimation
	shortAckDecimationDelay = 1.0 / 8
	// Minimum number of packets received before ack decimation is enabled.
	// This intends to avoid the beginning of slow start, when CWNDs may be
	// rapidly increasing.
	minReceivedBeforeAckDecimation = 100
	// Maximum number of packets to ack immediately after a missing packet for
	// fast retransmission to kick in at the sender.  This limit is created to
	// reduce the number of acks sent that have no benefit for fast retransmission.
	// Set to the number of nacks needed for fast retransmit plus one for protection
	// against an ack loss
	maxPacketsAfterNewMissing = 4
)

// NewReceivedPacketHandler creates a new receivedPacketHandler
func NewReceivedPacketHandler(
	rttStats *congestion.RTTStats,
	logger utils.Logger,
	version protocol.VersionNumber,
) ReceivedPacketHandler {
	return &receivedPacketHandler{
		packetHistory: newReceivedPacketHistory(),
		ackSendDelay:  ackSendDelay,
		rttStats:      rttStats,
		logger:        logger,
		version:       version,
	}
}

func (h *receivedPacketHandler) ReceivedPacket(packetNumber protocol.PacketNumber, rcvTime time.Time, shouldInstigateAck bool) error {
	if packetNumber < h.ignoreBelow {
		return nil
	}

	isMissing := h.isMissing(packetNumber)
	if packetNumber > h.largestObserved {
		h.largestObserved = packetNumber
		h.largestObservedReceivedTime = rcvTime
	}

	if err := h.packetHistory.ReceivedPacket(packetNumber); err != nil {
		return err
	}
	h.maybeQueueAck(packetNumber, rcvTime, shouldInstigateAck, isMissing)
	return nil
}

// IgnoreBelow sets a lower limit for acking packets.
// Packets with packet numbers smaller than p will not be acked.
func (h *receivedPacketHandler) IgnoreBelow(p protocol.PacketNumber) {
	if p <= h.ignoreBelow {
		return
	}
	h.ignoreBelow = p
	h.packetHistory.DeleteBelow(p)
	if h.logger.Debug() {
		h.logger.Debugf("\tIgnoring all packets below %#x.", p)
	}
}

// isMissing says if a packet was reported missing in the last ACK.
func (h *receivedPacketHandler) isMissing(p protocol.PacketNumber) bool {
	if h.lastAck == nil || p < h.ignoreBelow {
		return false
	}
	return p < h.lastAck.LargestAcked() && !h.lastAck.AcksPacket(p)
}

func (h *receivedPacketHandler) hasNewMissingPackets() bool {
	if h.lastAck == nil {
		return false
	}
	highestRange := h.packetHistory.GetHighestAckRange()
	return highestRange.Smallest >= h.lastAck.LargestAcked() && highestRange.Len() <= maxPacketsAfterNewMissing
}

// maybeQueueAck queues an ACK, if necessary.
// It is implemented analogously to Chrome's QuicConnection::MaybeQueueAck()
// in ACK_DECIMATION_WITH_REORDERING mode.
func (h *receivedPacketHandler) maybeQueueAck(packetNumber protocol.PacketNumber, rcvTime time.Time, shouldInstigateAck, wasMissing bool) {
	h.packetsReceivedSinceLastAck++

	// always ack the first packet
	if h.lastAck == nil {
		h.logger.Debugf("\tQueueing ACK because the first packet should be acknowledged.")
		h.ackQueued = true
		return
	}

	// Send an ACK if this packet was reported missing in an ACK sent before.
	// Ack decimation with reordering relies on the timer to send an ACK, but if
	// missing packets we reported in the previous ack, send an ACK immediately.
	if wasMissing {
		if h.logger.Debug() {
			h.logger.Debugf("\tQueueing ACK because packet %#x was missing before.", packetNumber)
		}
		h.ackQueued = true
	}

	if !h.ackQueued && shouldInstigateAck {
		h.retransmittablePacketsReceivedSinceLastAck++

		if packetNumber > minReceivedBeforeAckDecimation {
			// ack up to 10 packets at once
			if h.retransmittablePacketsReceivedSinceLastAck >= retransmittablePacketsBeforeAck {
				h.ackQueued = true
				if h.logger.Debug() {
					h.logger.Debugf("\tQueueing ACK because packet %d packets were received after the last ACK (using threshold: %d).", h.retransmittablePacketsReceivedSinceLastAck, retransmittablePacketsBeforeAck)
				}
			} else if h.ackAlarm.IsZero() {
				// wait for the minimum of the ack decimation delay or the delayed ack time before sending an ack
				ackDelay := utils.MinDuration(ackSendDelay, time.Duration(float64(h.rttStats.MinRTT())*float64(ackDecimationDelay)))
				h.ackAlarm = rcvTime.Add(ackDelay)
				if h.logger.Debug() {
					h.logger.Debugf("\tSetting ACK timer to min(1/4 min-RTT, max ack delay): %s (%s from now)", ackDelay, time.Until(h.ackAlarm))
				}
			}
		} else {
			// send an ACK every 2 retransmittable packets
			if h.retransmittablePacketsReceivedSinceLastAck >= initialRetransmittablePacketsBeforeAck {
				if h.logger.Debug() {
					h.logger.Debugf("\tQueueing ACK because packet %d packets were received after the last ACK (using initial threshold: %d).", h.retransmittablePacketsReceivedSinceLastAck, initialRetransmittablePacketsBeforeAck)
				}
				h.ackQueued = true
			} else if h.ackAlarm.IsZero() {
				if h.logger.Debug() {
					h.logger.Debugf("\tSetting ACK timer to max ack delay: %s", ackSendDelay)
				}
				h.ackAlarm = rcvTime.Add(ackSendDelay)
			}
		}
		// If there are new missing packets to report, set a short timer to send an ACK.
		if h.hasNewMissingPackets() {
			// wait the minimum of 1/8 min RTT and the existing ack time
			ackDelay := time.Duration(float64(h.rttStats.MinRTT()) * float64(shortAckDecimationDelay))
			ackTime := rcvTime.Add(ackDelay)
			if h.ackAlarm.IsZero() || h.ackAlarm.After(ackTime) {
				h.ackAlarm = ackTime
				if h.logger.Debug() {
					h.logger.Debugf("\tSetting ACK timer to 1/8 min-RTT: %s (%s from now)", ackDelay, time.Until(h.ackAlarm))
				}
			}
		}
	}

	if h.ackQueued {
		// cancel the ack alarm
		h.ackAlarm = time.Time{}
	}
}

func (h *receivedPacketHandler) GetAckFrame() *wire.AckFrame {
	now := time.Now()
	if !h.ackQueued && (h.ackAlarm.IsZero() || h.ackAlarm.After(now)) {
		return nil
	}
	if h.logger.Debug() && !h.ackQueued && !h.ackAlarm.IsZero() {
		h.logger.Debugf("Sending ACK because the ACK timer expired.")
	}

	ack := &wire.AckFrame{
		AckRanges: h.packetHistory.GetAckRanges(),
		DelayTime: now.Sub(h.largestObservedReceivedTime),
	}

	h.lastAck = ack
	h.ackAlarm = time.Time{}
	h.ackQueued = false
	h.packetsReceivedSinceLastAck = 0
	h.retransmittablePacketsReceivedSinceLastAck = 0
	return ack
}

func (h *receivedPacketHandler) GetAlarmTimeout() time.Time { return h.ackAlarm }
