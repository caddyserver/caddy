package ackhandler

import (
	"errors"
	"time"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
)

var (
	// ErrDuplicatePacket occurres when a duplicate packet is received
	ErrDuplicatePacket = errors.New("ReceivedPacketHandler: Duplicate Packet")
	// ErrPacketSmallerThanLastStopWaiting occurs when a packet arrives with a packet number smaller than the largest LeastUnacked of a StopWaitingFrame. If this error occurs, the packet should be ignored
	ErrPacketSmallerThanLastStopWaiting = errors.New("ReceivedPacketHandler: Packet number smaller than highest StopWaiting")
)

var errInvalidPacketNumber = errors.New("ReceivedPacketHandler: Invalid packet number")

type receivedPacketHandler struct {
	largestObserved             protocol.PacketNumber
	ignorePacketsBelow          protocol.PacketNumber
	largestObservedReceivedTime time.Time

	packetHistory *receivedPacketHistory

	ackSendDelay time.Duration

	packetsReceivedSinceLastAck                int
	retransmittablePacketsReceivedSinceLastAck int
	ackQueued                                  bool
	ackAlarm                                   time.Time
	ackAlarmResetCallback                      func(time.Time)
	lastAck                                    *frames.AckFrame
}

// NewReceivedPacketHandler creates a new receivedPacketHandler
func NewReceivedPacketHandler(ackAlarmResetCallback func(time.Time)) ReceivedPacketHandler {
	// create a stopped timer, see https://github.com/golang/go/issues/12721#issuecomment-143010182
	timer := time.NewTimer(0)
	<-timer.C

	return &receivedPacketHandler{
		packetHistory:         newReceivedPacketHistory(),
		ackAlarmResetCallback: ackAlarmResetCallback,
		ackSendDelay:          protocol.AckSendDelay,
	}
}

func (h *receivedPacketHandler) ReceivedPacket(packetNumber protocol.PacketNumber, shouldInstigateAck bool) error {
	if packetNumber == 0 {
		return errInvalidPacketNumber
	}

	// if the packet number is smaller than the largest LeastUnacked value of a StopWaiting we received, we cannot detect if this packet has a duplicate number
	// the packet has to be ignored anyway
	if packetNumber <= h.ignorePacketsBelow {
		return ErrPacketSmallerThanLastStopWaiting
	}

	if h.packetHistory.IsDuplicate(packetNumber) {
		return ErrDuplicatePacket
	}

	err := h.packetHistory.ReceivedPacket(packetNumber)
	if err != nil {
		return err
	}

	if packetNumber > h.largestObserved {
		h.largestObserved = packetNumber
		h.largestObservedReceivedTime = time.Now()
	}

	h.maybeQueueAck(packetNumber, shouldInstigateAck)
	return nil
}

func (h *receivedPacketHandler) ReceivedStopWaiting(f *frames.StopWaitingFrame) error {
	// ignore if StopWaiting is unneeded, because we already received a StopWaiting with a higher LeastUnacked
	if h.ignorePacketsBelow >= f.LeastUnacked {
		return nil
	}

	h.ignorePacketsBelow = f.LeastUnacked - 1

	h.packetHistory.DeleteBelow(f.LeastUnacked)
	return nil
}

func (h *receivedPacketHandler) maybeQueueAck(packetNumber protocol.PacketNumber, shouldInstigateAck bool) {
	var ackAlarmSet bool
	h.packetsReceivedSinceLastAck++

	if shouldInstigateAck {
		h.retransmittablePacketsReceivedSinceLastAck++
	}

	// always ack the first packet
	if h.lastAck == nil {
		h.ackQueued = true
	}

	// Always send an ack every 20 packets in order to allow the peer to discard
	// information from the SentPacketManager and provide an RTT measurement.
	if h.packetsReceivedSinceLastAck >= protocol.MaxPacketsReceivedBeforeAckSend {
		h.ackQueued = true
	}

	// if the packet number is smaller than the largest acked packet, it must have been reported missing with the last ACK
	// note that it cannot be a duplicate because they're already filtered out by ReceivedPacket()
	if h.lastAck != nil && packetNumber < h.lastAck.LargestAcked {
		h.ackQueued = true
	}

	// check if a new missing range above the previously was created
	if h.lastAck != nil && h.packetHistory.GetHighestAckRange().FirstPacketNumber > h.lastAck.LargestAcked {
		h.ackQueued = true
	}

	if !h.ackQueued && shouldInstigateAck {
		if h.retransmittablePacketsReceivedSinceLastAck >= protocol.RetransmittablePacketsBeforeAck {
			h.ackQueued = true
		} else {
			if h.ackAlarm.IsZero() {
				h.ackAlarm = time.Now().Add(h.ackSendDelay)
				ackAlarmSet = true
			}
		}
	}

	if h.ackQueued {
		// cancel the ack alarm
		h.ackAlarm = time.Time{}
		ackAlarmSet = false
	}

	if ackAlarmSet {
		h.ackAlarmResetCallback(h.ackAlarm)
	}
}

func (h *receivedPacketHandler) GetAckFrame() *frames.AckFrame {
	if !h.ackQueued && (h.ackAlarm.IsZero() || h.ackAlarm.After(time.Now())) {
		return nil
	}

	ackRanges := h.packetHistory.GetAckRanges()
	ack := &frames.AckFrame{
		LargestAcked:       h.largestObserved,
		LowestAcked:        ackRanges[len(ackRanges)-1].FirstPacketNumber,
		PacketReceivedTime: h.largestObservedReceivedTime,
	}

	if len(ackRanges) > 1 {
		ack.AckRanges = ackRanges
	}

	h.lastAck = ack
	h.ackAlarm = time.Time{}
	h.ackQueued = false
	h.packetsReceivedSinceLastAck = 0
	h.retransmittablePacketsReceivedSinceLastAck = 0

	return ack
}
