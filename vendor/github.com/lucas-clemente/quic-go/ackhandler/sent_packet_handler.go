package ackhandler

import (
	"errors"
	"fmt"
	"time"

	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
)

const (
	// Maximum reordering in time space before time based loss detection considers a packet lost.
	// In fraction of an RTT.
	timeReorderingFraction = 1.0 / 8
	// defaultRTOTimeout is the RTO time on new connections
	defaultRTOTimeout = 500 * time.Millisecond
	// Minimum time in the future an RTO alarm may be set for.
	minRTOTimeout = 200 * time.Millisecond
	// maxRTOTimeout is the maximum RTO time
	maxRTOTimeout = 60 * time.Second
)

var (
	// ErrDuplicateOrOutOfOrderAck occurs when a duplicate or an out-of-order ACK is received
	ErrDuplicateOrOutOfOrderAck = errors.New("SentPacketHandler: Duplicate or out-of-order ACK")
	// ErrTooManyTrackedSentPackets occurs when the sentPacketHandler has to keep track of too many packets
	ErrTooManyTrackedSentPackets = errors.New("Too many outstanding non-acked and non-retransmitted packets")
	// ErrAckForSkippedPacket occurs when the client sent an ACK for a packet number that we intentionally skipped
	ErrAckForSkippedPacket = qerr.Error(qerr.InvalidAckData, "Received an ACK for a skipped packet number")
	errAckForUnsentPacket  = qerr.Error(qerr.InvalidAckData, "Received ACK for an unsent package")
)

var errPacketNumberNotIncreasing = errors.New("Already sent a packet with a higher packet number")

type sentPacketHandler struct {
	lastSentPacketNumber protocol.PacketNumber
	skippedPackets       []protocol.PacketNumber

	LargestAcked protocol.PacketNumber

	largestReceivedPacketWithAck protocol.PacketNumber

	packetHistory      *PacketList
	stopWaitingManager stopWaitingManager

	retransmissionQueue []*Packet

	bytesInFlight protocol.ByteCount

	congestion congestion.SendAlgorithm
	rttStats   *congestion.RTTStats

	// The number of times an RTO has been sent without receiving an ack.
	rtoCount uint32

	// The time at which the next packet will be considered lost based on early transmit or exceeding the reordering window in time.
	lossTime time.Time

	// The alarm timeout
	alarm time.Time
}

// NewSentPacketHandler creates a new sentPacketHandler
func NewSentPacketHandler(rttStats *congestion.RTTStats) SentPacketHandler {
	congestion := congestion.NewCubicSender(
		congestion.DefaultClock{},
		rttStats,
		false, /* don't use reno since chromium doesn't (why?) */
		protocol.InitialCongestionWindow,
		protocol.DefaultMaxCongestionWindow,
	)

	return &sentPacketHandler{
		packetHistory:      NewPacketList(),
		stopWaitingManager: stopWaitingManager{},
		rttStats:           rttStats,
		congestion:         congestion,
	}
}

func (h *sentPacketHandler) largestInOrderAcked() protocol.PacketNumber {
	if f := h.packetHistory.Front(); f != nil {
		return f.Value.PacketNumber - 1
	}
	return h.LargestAcked
}

func (h *sentPacketHandler) SentPacket(packet *Packet) error {
	if packet.PacketNumber <= h.lastSentPacketNumber {
		return errPacketNumberNotIncreasing
	}

	if protocol.PacketNumber(len(h.retransmissionQueue)+h.packetHistory.Len()+1) > protocol.MaxTrackedSentPackets {
		return ErrTooManyTrackedSentPackets
	}

	for p := h.lastSentPacketNumber + 1; p < packet.PacketNumber; p++ {
		h.skippedPackets = append(h.skippedPackets, p)

		if len(h.skippedPackets) > protocol.MaxTrackedSkippedPackets {
			h.skippedPackets = h.skippedPackets[1:]
		}
	}

	h.lastSentPacketNumber = packet.PacketNumber
	now := time.Now()

	packet.Frames = stripNonRetransmittableFrames(packet.Frames)
	isRetransmittable := len(packet.Frames) != 0

	if isRetransmittable {
		packet.SendTime = now
		h.bytesInFlight += packet.Length
		h.packetHistory.PushBack(*packet)
	}

	h.congestion.OnPacketSent(
		now,
		h.bytesInFlight,
		packet.PacketNumber,
		packet.Length,
		isRetransmittable,
	)

	h.updateLossDetectionAlarm()
	return nil
}

func (h *sentPacketHandler) ReceivedAck(ackFrame *frames.AckFrame, withPacketNumber protocol.PacketNumber, rcvTime time.Time) error {
	if ackFrame.LargestAcked > h.lastSentPacketNumber {
		return errAckForUnsentPacket
	}

	// duplicate or out-of-order ACK
	if withPacketNumber <= h.largestReceivedPacketWithAck {
		return ErrDuplicateOrOutOfOrderAck
	}
	h.largestReceivedPacketWithAck = withPacketNumber

	// ignore repeated ACK (ACKs that don't have a higher LargestAcked than the last ACK)
	if ackFrame.LargestAcked <= h.largestInOrderAcked() {
		return nil
	}
	h.LargestAcked = ackFrame.LargestAcked

	if h.skippedPacketsAcked(ackFrame) {
		return ErrAckForSkippedPacket
	}

	rttUpdated := h.maybeUpdateRTT(ackFrame.LargestAcked, ackFrame.DelayTime, rcvTime)

	if rttUpdated {
		h.congestion.MaybeExitSlowStart()
	}

	ackedPackets, err := h.determineNewlyAckedPackets(ackFrame)
	if err != nil {
		return err
	}

	if len(ackedPackets) > 0 {
		for _, p := range ackedPackets {
			h.onPacketAcked(p)
			h.congestion.OnPacketAcked(p.Value.PacketNumber, p.Value.Length, h.bytesInFlight)
		}
	}

	h.detectLostPackets()
	h.updateLossDetectionAlarm()

	h.garbageCollectSkippedPackets()
	h.stopWaitingManager.ReceivedAck(ackFrame)

	return nil
}

func (h *sentPacketHandler) determineNewlyAckedPackets(ackFrame *frames.AckFrame) ([]*PacketElement, error) {
	var ackedPackets []*PacketElement
	ackRangeIndex := 0
	for el := h.packetHistory.Front(); el != nil; el = el.Next() {
		packet := el.Value
		packetNumber := packet.PacketNumber

		// Ignore packets below the LowestAcked
		if packetNumber < ackFrame.LowestAcked {
			continue
		}
		// Break after LargestAcked is reached
		if packetNumber > ackFrame.LargestAcked {
			break
		}

		if ackFrame.HasMissingRanges() {
			ackRange := ackFrame.AckRanges[len(ackFrame.AckRanges)-1-ackRangeIndex]

			for packetNumber > ackRange.LastPacketNumber && ackRangeIndex < len(ackFrame.AckRanges)-1 {
				ackRangeIndex++
				ackRange = ackFrame.AckRanges[len(ackFrame.AckRanges)-1-ackRangeIndex]
			}

			if packetNumber >= ackRange.FirstPacketNumber { // packet i contained in ACK range
				if packetNumber > ackRange.LastPacketNumber {
					return nil, fmt.Errorf("BUG: ackhandler would have acked wrong packet 0x%x, while evaluating range 0x%x -> 0x%x", packetNumber, ackRange.FirstPacketNumber, ackRange.LastPacketNumber)
				}
				ackedPackets = append(ackedPackets, el)
			}
		} else {
			ackedPackets = append(ackedPackets, el)
		}
	}

	return ackedPackets, nil
}

func (h *sentPacketHandler) maybeUpdateRTT(largestAcked protocol.PacketNumber, ackDelay time.Duration, rcvTime time.Time) bool {
	for el := h.packetHistory.Front(); el != nil; el = el.Next() {
		packet := el.Value
		if packet.PacketNumber == largestAcked {
			h.rttStats.UpdateRTT(rcvTime.Sub(packet.SendTime), ackDelay, time.Now())
			return true
		}
		// Packets are sorted by number, so we can stop searching
		if packet.PacketNumber > largestAcked {
			break
		}
	}
	return false
}

func (h *sentPacketHandler) updateLossDetectionAlarm() {
	// Cancel the alarm if no packets are outstanding
	if h.packetHistory.Len() == 0 {
		h.alarm = time.Time{}
		return
	}

	// TODO(#496): Handle handshake packets separately
	// TODO(#497): TLP
	if !h.lossTime.IsZero() {
		// Early retransmit timer or time loss detection.
		h.alarm = h.lossTime
	} else {
		// RTO
		h.alarm = time.Now().Add(h.computeRTOTimeout())
	}
}

func (h *sentPacketHandler) detectLostPackets() {
	h.lossTime = time.Time{}
	now := time.Now()

	maxRTT := float64(utils.MaxDuration(h.rttStats.LatestRTT(), h.rttStats.SmoothedRTT()))
	delayUntilLost := time.Duration((1.0 + timeReorderingFraction) * maxRTT)

	var lostPackets []*PacketElement
	for el := h.packetHistory.Front(); el != nil; el = el.Next() {
		packet := el.Value

		if packet.PacketNumber > h.LargestAcked {
			break
		}

		timeSinceSent := now.Sub(packet.SendTime)
		if timeSinceSent > delayUntilLost {
			lostPackets = append(lostPackets, el)
		} else if h.lossTime.IsZero() {
			// Note: This conditional is only entered once per call
			h.lossTime = now.Add(delayUntilLost - timeSinceSent)
		}
	}

	if len(lostPackets) > 0 {
		for _, p := range lostPackets {
			h.queuePacketForRetransmission(p)
			h.congestion.OnPacketLost(p.Value.PacketNumber, p.Value.Length, h.bytesInFlight)
		}
	}
}

func (h *sentPacketHandler) OnAlarm() {
	// TODO(#496): Handle handshake packets separately
	// TODO(#497): TLP
	if !h.lossTime.IsZero() {
		// Early retransmit or time loss detection
		h.detectLostPackets()
	} else {
		// RTO
		h.retransmitOldestTwoPackets()
		h.rtoCount++
	}

	h.updateLossDetectionAlarm()
}

func (h *sentPacketHandler) GetAlarmTimeout() time.Time {
	return h.alarm
}

func (h *sentPacketHandler) onPacketAcked(packetElement *PacketElement) {
	h.bytesInFlight -= packetElement.Value.Length
	h.rtoCount = 0
	// TODO(#497): h.tlpCount = 0
	h.packetHistory.Remove(packetElement)
}

func (h *sentPacketHandler) DequeuePacketForRetransmission() *Packet {
	if len(h.retransmissionQueue) == 0 {
		return nil
	}
	packet := h.retransmissionQueue[0]
	// Shift the slice and don't retain anything that isn't needed.
	copy(h.retransmissionQueue, h.retransmissionQueue[1:])
	h.retransmissionQueue[len(h.retransmissionQueue)-1] = nil
	h.retransmissionQueue = h.retransmissionQueue[:len(h.retransmissionQueue)-1]
	return packet
}

func (h *sentPacketHandler) GetLeastUnacked() protocol.PacketNumber {
	return h.largestInOrderAcked() + 1
}

func (h *sentPacketHandler) GetStopWaitingFrame(force bool) *frames.StopWaitingFrame {
	return h.stopWaitingManager.GetStopWaitingFrame(force)
}

func (h *sentPacketHandler) SendingAllowed() bool {
	congestionLimited := h.bytesInFlight > h.congestion.GetCongestionWindow()
	maxTrackedLimited := protocol.PacketNumber(len(h.retransmissionQueue)+h.packetHistory.Len()) >= protocol.MaxTrackedSentPackets
	if congestionLimited {
		utils.Debugf("Congestion limited: bytes in flight %d, window %d",
			h.bytesInFlight,
			h.congestion.GetCongestionWindow())
	}
	// Workaround for #555:
	// Always allow sending of retransmissions. This should probably be limited
	// to RTOs, but we currently don't have a nice way of distinguishing them.
	haveRetransmissions := len(h.retransmissionQueue) > 0
	return !maxTrackedLimited && (!congestionLimited || haveRetransmissions)
}

func (h *sentPacketHandler) retransmitOldestTwoPackets() {
	if p := h.packetHistory.Front(); p != nil {
		h.queueRTO(p)
	}
	if p := h.packetHistory.Front(); p != nil {
		h.queueRTO(p)
	}
}

func (h *sentPacketHandler) queueRTO(el *PacketElement) {
	packet := &el.Value
	utils.Debugf(
		"\tQueueing packet 0x%x for retransmission (RTO), %d outstanding",
		packet.PacketNumber,
		h.packetHistory.Len(),
	)
	h.queuePacketForRetransmission(el)
	h.congestion.OnPacketLost(packet.PacketNumber, packet.Length, h.bytesInFlight)
	h.congestion.OnRetransmissionTimeout(true)
}

func (h *sentPacketHandler) queuePacketForRetransmission(packetElement *PacketElement) {
	packet := &packetElement.Value
	h.bytesInFlight -= packet.Length
	h.retransmissionQueue = append(h.retransmissionQueue, packet)
	h.packetHistory.Remove(packetElement)
	h.stopWaitingManager.QueuedRetransmissionForPacketNumber(packet.PacketNumber)
}

func (h *sentPacketHandler) computeRTOTimeout() time.Duration {
	rto := h.congestion.RetransmissionDelay()
	if rto == 0 {
		rto = defaultRTOTimeout
	}
	rto = utils.MaxDuration(rto, minRTOTimeout)
	// Exponential backoff
	rto = rto << h.rtoCount
	return utils.MinDuration(rto, maxRTOTimeout)
}

func (h *sentPacketHandler) skippedPacketsAcked(ackFrame *frames.AckFrame) bool {
	for _, p := range h.skippedPackets {
		if ackFrame.AcksPacket(p) {
			return true
		}
	}
	return false
}

func (h *sentPacketHandler) garbageCollectSkippedPackets() {
	lioa := h.largestInOrderAcked()
	deleteIndex := 0
	for i, p := range h.skippedPackets {
		if p <= lioa {
			deleteIndex = i + 1
		}
	}
	h.skippedPackets = h.skippedPackets[deleteIndex:]
}
