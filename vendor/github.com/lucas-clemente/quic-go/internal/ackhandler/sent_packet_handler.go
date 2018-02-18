package ackhandler

import (
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/lucas-clemente/quic-go/internal/congestion"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"github.com/lucas-clemente/quic-go/qerr"
)

const (
	// Maximum reordering in time space before time based loss detection considers a packet lost.
	// In fraction of an RTT.
	timeReorderingFraction = 1.0 / 8
	// The default RTT used before an RTT sample is taken.
	// Note: This constant is also defined in the congestion package.
	defaultInitialRTT = 100 * time.Millisecond
	// defaultRTOTimeout is the RTO time on new connections
	defaultRTOTimeout = 500 * time.Millisecond
	// Minimum time in the future a tail loss probe alarm may be set for.
	minTPLTimeout = 10 * time.Millisecond
	// Minimum time in the future an RTO alarm may be set for.
	minRTOTimeout = 200 * time.Millisecond
	// maxRTOTimeout is the maximum RTO time
	maxRTOTimeout = 60 * time.Second
)

// ErrDuplicateOrOutOfOrderAck occurs when a duplicate or an out-of-order ACK is received
var ErrDuplicateOrOutOfOrderAck = errors.New("SentPacketHandler: Duplicate or out-of-order ACK")

type sentPacketHandler struct {
	lastSentPacketNumber protocol.PacketNumber
	nextPacketSendTime   time.Time
	skippedPackets       []protocol.PacketNumber

	largestAcked                 protocol.PacketNumber
	largestReceivedPacketWithAck protocol.PacketNumber
	// lowestPacketNotConfirmedAcked is the lowest packet number that we sent an ACK for, but haven't received confirmation, that this ACK actually arrived
	// example: we send an ACK for packets 90-100 with packet number 20
	// once we receive an ACK from the peer for packet 20, the lowestPacketNotConfirmedAcked is 101
	lowestPacketNotConfirmedAcked protocol.PacketNumber

	packetHistory      *PacketList
	stopWaitingManager stopWaitingManager

	retransmissionQueue []*Packet

	bytesInFlight protocol.ByteCount

	congestion congestion.SendAlgorithm
	rttStats   *congestion.RTTStats

	handshakeComplete bool
	// The number of times the handshake packets have been retransmitted without receiving an ack.
	handshakeCount uint32

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

func (h *sentPacketHandler) lowestUnacked() protocol.PacketNumber {
	if f := h.packetHistory.Front(); f != nil {
		return f.Value.PacketNumber
	}
	return h.largestAcked + 1
}

func (h *sentPacketHandler) SetHandshakeComplete() {
	var queue []*Packet
	for _, packet := range h.retransmissionQueue {
		if packet.EncryptionLevel == protocol.EncryptionForwardSecure {
			queue = append(queue, packet)
		}
	}
	h.retransmissionQueue = queue
	h.handshakeComplete = true
}

func (h *sentPacketHandler) SentPacket(packet *Packet) error {
	if protocol.PacketNumber(len(h.retransmissionQueue)+h.packetHistory.Len()+1) > protocol.MaxTrackedSentPackets {
		return errors.New("Too many outstanding non-acked and non-retransmitted packets")
	}

	for p := h.lastSentPacketNumber + 1; p < packet.PacketNumber; p++ {
		h.skippedPackets = append(h.skippedPackets, p)

		if len(h.skippedPackets) > protocol.MaxTrackedSkippedPackets {
			h.skippedPackets = h.skippedPackets[1:]
		}
	}

	now := time.Now()
	h.lastSentPacketNumber = packet.PacketNumber

	var largestAcked protocol.PacketNumber
	if len(packet.Frames) > 0 {
		if ackFrame, ok := packet.Frames[0].(*wire.AckFrame); ok {
			largestAcked = ackFrame.LargestAcked
		}
	}

	packet.Frames = stripNonRetransmittableFrames(packet.Frames)
	isRetransmittable := len(packet.Frames) != 0

	if isRetransmittable {
		packet.sendTime = now
		packet.largestAcked = largestAcked
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

	h.nextPacketSendTime = utils.MaxTime(h.nextPacketSendTime, now).Add(h.congestion.TimeUntilSend(h.bytesInFlight))

	h.updateLossDetectionAlarm(now)
	return nil
}

func (h *sentPacketHandler) ReceivedAck(ackFrame *wire.AckFrame, withPacketNumber protocol.PacketNumber, encLevel protocol.EncryptionLevel, rcvTime time.Time) error {
	if ackFrame.LargestAcked > h.lastSentPacketNumber {
		return qerr.Error(qerr.InvalidAckData, "Received ACK for an unsent package")
	}

	// duplicate or out-of-order ACK
	// if withPacketNumber <= h.largestReceivedPacketWithAck && withPacketNumber != 0 {
	if withPacketNumber <= h.largestReceivedPacketWithAck {
		return ErrDuplicateOrOutOfOrderAck
	}
	h.largestReceivedPacketWithAck = withPacketNumber

	// ignore repeated ACK (ACKs that don't have a higher LargestAcked than the last ACK)
	if ackFrame.LargestAcked < h.lowestUnacked() {
		return nil
	}
	h.largestAcked = ackFrame.LargestAcked

	if h.skippedPacketsAcked(ackFrame) {
		return qerr.Error(qerr.InvalidAckData, "Received an ACK for a skipped packet number")
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
			if encLevel < p.Value.EncryptionLevel {
				return fmt.Errorf("Received ACK with encryption level %s that acks a packet %d (encryption level %s)", encLevel, p.Value.PacketNumber, p.Value.EncryptionLevel)
			}
			// largestAcked == 0 either means that the packet didn't contain an ACK, or it just acked packet 0
			// It is safe to ignore the corner case of packets that just acked packet 0, because
			// the lowestPacketNotConfirmedAcked is only used to limit the number of ACK ranges we will send.
			if p.Value.largestAcked != 0 {
				h.lowestPacketNotConfirmedAcked = utils.MaxPacketNumber(h.lowestPacketNotConfirmedAcked, p.Value.largestAcked+1)
			}
			h.onPacketAcked(p)
			h.congestion.OnPacketAcked(p.Value.PacketNumber, p.Value.Length, h.bytesInFlight)
		}
	}

	h.detectLostPackets(rcvTime)
	h.updateLossDetectionAlarm(rcvTime)

	h.garbageCollectSkippedPackets()
	h.stopWaitingManager.ReceivedAck(ackFrame)

	return nil
}

func (h *sentPacketHandler) GetLowestPacketNotConfirmedAcked() protocol.PacketNumber {
	return h.lowestPacketNotConfirmedAcked
}

func (h *sentPacketHandler) determineNewlyAckedPackets(ackFrame *wire.AckFrame) ([]*PacketElement, error) {
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

			for packetNumber > ackRange.Last && ackRangeIndex < len(ackFrame.AckRanges)-1 {
				ackRangeIndex++
				ackRange = ackFrame.AckRanges[len(ackFrame.AckRanges)-1-ackRangeIndex]
			}

			if packetNumber >= ackRange.First { // packet i contained in ACK range
				if packetNumber > ackRange.Last {
					return nil, fmt.Errorf("BUG: ackhandler would have acked wrong packet 0x%x, while evaluating range 0x%x -> 0x%x", packetNumber, ackRange.First, ackRange.Last)
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
			h.rttStats.UpdateRTT(rcvTime.Sub(packet.sendTime), ackDelay, rcvTime)
			return true
		}
		// Packets are sorted by number, so we can stop searching
		if packet.PacketNumber > largestAcked {
			break
		}
	}
	return false
}

func (h *sentPacketHandler) updateLossDetectionAlarm(now time.Time) {
	// Cancel the alarm if no packets are outstanding
	if h.packetHistory.Len() == 0 {
		h.alarm = time.Time{}
		return
	}

	// TODO(#497): TLP
	if !h.handshakeComplete {
		h.alarm = now.Add(h.computeHandshakeTimeout())
	} else if !h.lossTime.IsZero() {
		// Early retransmit timer or time loss detection.
		h.alarm = h.lossTime
	} else {
		// RTO
		h.alarm = now.Add(h.computeRTOTimeout())
	}
}

func (h *sentPacketHandler) detectLostPackets(now time.Time) {
	h.lossTime = time.Time{}

	maxRTT := float64(utils.MaxDuration(h.rttStats.LatestRTT(), h.rttStats.SmoothedRTT()))
	delayUntilLost := time.Duration((1.0 + timeReorderingFraction) * maxRTT)

	var lostPackets []*PacketElement
	for el := h.packetHistory.Front(); el != nil; el = el.Next() {
		packet := el.Value

		if packet.PacketNumber > h.largestAcked {
			break
		}

		timeSinceSent := now.Sub(packet.sendTime)
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
	now := time.Now()

	// TODO(#497): TLP
	if !h.handshakeComplete {
		h.queueHandshakePacketsForRetransmission()
		h.handshakeCount++
	} else if !h.lossTime.IsZero() {
		// Early retransmit or time loss detection
		h.detectLostPackets(now)
	} else {
		// RTO
		h.retransmitOldestTwoPackets()
		h.rtoCount++
	}

	h.updateLossDetectionAlarm(now)
}

func (h *sentPacketHandler) GetAlarmTimeout() time.Time {
	return h.alarm
}

func (h *sentPacketHandler) onPacketAcked(packetElement *PacketElement) {
	h.bytesInFlight -= packetElement.Value.Length
	h.rtoCount = 0
	h.handshakeCount = 0
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
	return h.lowestUnacked()
}

func (h *sentPacketHandler) GetStopWaitingFrame(force bool) *wire.StopWaitingFrame {
	return h.stopWaitingManager.GetStopWaitingFrame(force)
}

func (h *sentPacketHandler) SendingAllowed() bool {
	cwnd := h.congestion.GetCongestionWindow()
	congestionLimited := h.bytesInFlight > cwnd
	maxTrackedLimited := protocol.PacketNumber(len(h.retransmissionQueue)+h.packetHistory.Len()) >= protocol.MaxTrackedSentPackets
	if congestionLimited {
		utils.Debugf("Congestion limited: bytes in flight %d, window %d", h.bytesInFlight, cwnd)
	}
	// Workaround for #555:
	// Always allow sending of retransmissions. This should probably be limited
	// to RTOs, but we currently don't have a nice way of distinguishing them.
	haveRetransmissions := len(h.retransmissionQueue) > 0
	return !maxTrackedLimited && (!congestionLimited || haveRetransmissions)
}

func (h *sentPacketHandler) TimeUntilSend() time.Time {
	return h.nextPacketSendTime
}

func (h *sentPacketHandler) ShouldSendNumPackets() int {
	delay := h.congestion.TimeUntilSend(h.bytesInFlight)
	if delay == 0 || delay > protocol.MinPacingDelay {
		return 1
	}
	return int(math.Ceil(float64(protocol.MinPacingDelay) / float64(delay)))
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

func (h *sentPacketHandler) queueHandshakePacketsForRetransmission() {
	var handshakePackets []*PacketElement
	for el := h.packetHistory.Front(); el != nil; el = el.Next() {
		if el.Value.EncryptionLevel < protocol.EncryptionForwardSecure {
			handshakePackets = append(handshakePackets, el)
		}
	}
	for _, el := range handshakePackets {
		h.queuePacketForRetransmission(el)
	}
}

func (h *sentPacketHandler) queuePacketForRetransmission(packetElement *PacketElement) {
	packet := &packetElement.Value
	h.bytesInFlight -= packet.Length
	h.retransmissionQueue = append(h.retransmissionQueue, packet)
	h.packetHistory.Remove(packetElement)
	h.stopWaitingManager.QueuedRetransmissionForPacketNumber(packet.PacketNumber)
}

func (h *sentPacketHandler) computeHandshakeTimeout() time.Duration {
	duration := 2 * h.rttStats.SmoothedRTT()
	if duration == 0 {
		duration = 2 * defaultInitialRTT
	}
	duration = utils.MaxDuration(duration, minTPLTimeout)
	// exponential backoff
	// There's an implicit limit to this set by the handshake timeout.
	return duration << h.handshakeCount
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

func (h *sentPacketHandler) skippedPacketsAcked(ackFrame *wire.AckFrame) bool {
	for _, p := range h.skippedPackets {
		if ackFrame.AcksPacket(p) {
			return true
		}
	}
	return false
}

func (h *sentPacketHandler) garbageCollectSkippedPackets() {
	lowestUnacked := h.lowestUnacked()
	deleteIndex := 0
	for i, p := range h.skippedPackets {
		if p < lowestUnacked {
			deleteIndex = i + 1
		}
	}
	h.skippedPackets = h.skippedPackets[deleteIndex:]
}
