package ackhandler

import (
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

type sentPacketHandler struct {
	lastSentPacketNumber              protocol.PacketNumber
	lastSentRetransmittablePacketTime time.Time
	lastSentHandshakePacketTime       time.Time

	nextPacketSendTime time.Time
	skippedPackets     []protocol.PacketNumber

	largestAcked                 protocol.PacketNumber
	largestReceivedPacketWithAck protocol.PacketNumber
	// lowestPacketNotConfirmedAcked is the lowest packet number that we sent an ACK for, but haven't received confirmation, that this ACK actually arrived
	// example: we send an ACK for packets 90-100 with packet number 20
	// once we receive an ACK from the peer for packet 20, the lowestPacketNotConfirmedAcked is 101
	lowestPacketNotConfirmedAcked protocol.PacketNumber
	largestSentBeforeRTO          protocol.PacketNumber

	packetHistory      *sentPacketHistory
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
	// The number of RTO probe packets that should be sent.
	numRTOs int

	// The time at which the next packet will be considered lost based on early transmit or exceeding the reordering window in time.
	lossTime time.Time

	// The alarm timeout
	alarm time.Time

	logger utils.Logger
}

// NewSentPacketHandler creates a new sentPacketHandler
func NewSentPacketHandler(rttStats *congestion.RTTStats, logger utils.Logger) SentPacketHandler {
	congestion := congestion.NewCubicSender(
		congestion.DefaultClock{},
		rttStats,
		false, /* don't use reno since chromium doesn't (why?) */
		protocol.InitialCongestionWindow,
		protocol.DefaultMaxCongestionWindow,
	)

	return &sentPacketHandler{
		packetHistory:      newSentPacketHistory(),
		stopWaitingManager: stopWaitingManager{},
		rttStats:           rttStats,
		congestion:         congestion,
		logger:             logger,
	}
}

func (h *sentPacketHandler) lowestUnacked() protocol.PacketNumber {
	if p := h.packetHistory.FirstOutstanding(); p != nil {
		return p.PacketNumber
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
	var handshakePackets []*Packet
	h.packetHistory.Iterate(func(p *Packet) (bool, error) {
		if p.EncryptionLevel != protocol.EncryptionForwardSecure {
			handshakePackets = append(handshakePackets, p)
		}
		return true, nil
	})
	for _, p := range handshakePackets {
		h.packetHistory.Remove(p.PacketNumber)
	}
	h.retransmissionQueue = queue
	h.handshakeComplete = true
}

func (h *sentPacketHandler) SentPacket(packet *Packet) {
	if isRetransmittable := h.sentPacketImpl(packet); isRetransmittable {
		h.packetHistory.SentPacket(packet)
		h.updateLossDetectionAlarm()
	}
}

func (h *sentPacketHandler) SentPacketsAsRetransmission(packets []*Packet, retransmissionOf protocol.PacketNumber) {
	var p []*Packet
	for _, packet := range packets {
		if isRetransmittable := h.sentPacketImpl(packet); isRetransmittable {
			p = append(p, packet)
		}
	}
	h.packetHistory.SentPacketsAsRetransmission(p, retransmissionOf)
	h.updateLossDetectionAlarm()
}

func (h *sentPacketHandler) sentPacketImpl(packet *Packet) bool /* isRetransmittable */ {
	for p := h.lastSentPacketNumber + 1; p < packet.PacketNumber; p++ {
		h.skippedPackets = append(h.skippedPackets, p)
		if len(h.skippedPackets) > protocol.MaxTrackedSkippedPackets {
			h.skippedPackets = h.skippedPackets[1:]
		}
	}

	h.lastSentPacketNumber = packet.PacketNumber

	if len(packet.Frames) > 0 {
		if ackFrame, ok := packet.Frames[0].(*wire.AckFrame); ok {
			packet.largestAcked = ackFrame.LargestAcked
		}
	}

	packet.Frames = stripNonRetransmittableFrames(packet.Frames)
	isRetransmittable := len(packet.Frames) != 0

	if isRetransmittable {
		if packet.EncryptionLevel < protocol.EncryptionForwardSecure {
			h.lastSentHandshakePacketTime = packet.SendTime
		}
		h.lastSentRetransmittablePacketTime = packet.SendTime
		packet.includedInBytesInFlight = true
		h.bytesInFlight += packet.Length
		packet.canBeRetransmitted = true
		if h.numRTOs > 0 {
			h.numRTOs--
		}
	}
	h.congestion.OnPacketSent(packet.SendTime, h.bytesInFlight, packet.PacketNumber, packet.Length, isRetransmittable)

	h.nextPacketSendTime = utils.MaxTime(h.nextPacketSendTime, packet.SendTime).Add(h.congestion.TimeUntilSend(h.bytesInFlight))
	return isRetransmittable
}

func (h *sentPacketHandler) ReceivedAck(ackFrame *wire.AckFrame, withPacketNumber protocol.PacketNumber, encLevel protocol.EncryptionLevel, rcvTime time.Time) error {
	if ackFrame.LargestAcked > h.lastSentPacketNumber {
		return qerr.Error(qerr.InvalidAckData, "Received ACK for an unsent package")
	}

	// duplicate or out of order ACK
	if withPacketNumber != 0 && withPacketNumber <= h.largestReceivedPacketWithAck {
		h.logger.Debugf("Ignoring ACK frame (duplicate or out of order).")
		return nil
	}
	h.largestReceivedPacketWithAck = withPacketNumber
	h.largestAcked = utils.MaxPacketNumber(h.largestAcked, ackFrame.LargestAcked)

	if h.skippedPacketsAcked(ackFrame) {
		return qerr.Error(qerr.InvalidAckData, "Received an ACK for a skipped packet number")
	}

	if rttUpdated := h.maybeUpdateRTT(ackFrame.LargestAcked, ackFrame.DelayTime, rcvTime); rttUpdated {
		h.congestion.MaybeExitSlowStart()
	}

	ackedPackets, err := h.determineNewlyAckedPackets(ackFrame)
	if err != nil {
		return err
	}

	priorInFlight := h.bytesInFlight
	for _, p := range ackedPackets {
		if encLevel < p.EncryptionLevel {
			return fmt.Errorf("Received ACK with encryption level %s that acks a packet %d (encryption level %s)", encLevel, p.PacketNumber, p.EncryptionLevel)
		}
		// largestAcked == 0 either means that the packet didn't contain an ACK, or it just acked packet 0
		// It is safe to ignore the corner case of packets that just acked packet 0, because
		// the lowestPacketNotConfirmedAcked is only used to limit the number of ACK ranges we will send.
		if p.largestAcked != 0 {
			h.lowestPacketNotConfirmedAcked = utils.MaxPacketNumber(h.lowestPacketNotConfirmedAcked, p.largestAcked+1)
		}
		if err := h.onPacketAcked(p); err != nil {
			return err
		}
		if p.includedInBytesInFlight {
			h.congestion.OnPacketAcked(p.PacketNumber, p.Length, priorInFlight)
		}
	}

	if err := h.detectLostPackets(rcvTime, priorInFlight); err != nil {
		return err
	}
	h.updateLossDetectionAlarm()

	h.garbageCollectSkippedPackets()
	h.stopWaitingManager.ReceivedAck(ackFrame)

	return nil
}

func (h *sentPacketHandler) GetLowestPacketNotConfirmedAcked() protocol.PacketNumber {
	return h.lowestPacketNotConfirmedAcked
}

func (h *sentPacketHandler) determineNewlyAckedPackets(ackFrame *wire.AckFrame) ([]*Packet, error) {
	var ackedPackets []*Packet
	ackRangeIndex := 0
	err := h.packetHistory.Iterate(func(p *Packet) (bool, error) {
		// Ignore packets below the LowestAcked
		if p.PacketNumber < ackFrame.LowestAcked {
			return true, nil
		}
		// Break after LargestAcked is reached
		if p.PacketNumber > ackFrame.LargestAcked {
			return false, nil
		}

		if ackFrame.HasMissingRanges() {
			ackRange := ackFrame.AckRanges[len(ackFrame.AckRanges)-1-ackRangeIndex]

			for p.PacketNumber > ackRange.Last && ackRangeIndex < len(ackFrame.AckRanges)-1 {
				ackRangeIndex++
				ackRange = ackFrame.AckRanges[len(ackFrame.AckRanges)-1-ackRangeIndex]
			}

			if p.PacketNumber >= ackRange.First { // packet i contained in ACK range
				if p.PacketNumber > ackRange.Last {
					return false, fmt.Errorf("BUG: ackhandler would have acked wrong packet 0x%x, while evaluating range 0x%x -> 0x%x", p.PacketNumber, ackRange.First, ackRange.Last)
				}
				ackedPackets = append(ackedPackets, p)
			}
		} else {
			ackedPackets = append(ackedPackets, p)
		}
		return true, nil
	})
	return ackedPackets, err
}

func (h *sentPacketHandler) maybeUpdateRTT(largestAcked protocol.PacketNumber, ackDelay time.Duration, rcvTime time.Time) bool {
	if p := h.packetHistory.GetPacket(largestAcked); p != nil {
		h.rttStats.UpdateRTT(rcvTime.Sub(p.SendTime), ackDelay, rcvTime)
		return true
	}
	return false
}

func (h *sentPacketHandler) updateLossDetectionAlarm() {
	// Cancel the alarm if no packets are outstanding
	if h.packetHistory.Len() == 0 {
		h.alarm = time.Time{}
		return
	}

	// TODO(#497): TLP
	if !h.handshakeComplete {
		h.alarm = h.lastSentHandshakePacketTime.Add(h.computeHandshakeTimeout())
	} else if !h.lossTime.IsZero() {
		// Early retransmit timer or time loss detection.
		h.alarm = h.lossTime
	} else {
		// RTO
		h.alarm = h.lastSentRetransmittablePacketTime.Add(h.computeRTOTimeout())
	}
}

func (h *sentPacketHandler) detectLostPackets(now time.Time, priorInFlight protocol.ByteCount) error {
	h.lossTime = time.Time{}

	maxRTT := float64(utils.MaxDuration(h.rttStats.LatestRTT(), h.rttStats.SmoothedRTT()))
	delayUntilLost := time.Duration((1.0 + timeReorderingFraction) * maxRTT)

	var lostPackets []*Packet
	h.packetHistory.Iterate(func(packet *Packet) (bool, error) {
		if packet.PacketNumber > h.largestAcked {
			return false, nil
		}

		timeSinceSent := now.Sub(packet.SendTime)
		if timeSinceSent > delayUntilLost {
			lostPackets = append(lostPackets, packet)
		} else if h.lossTime.IsZero() {
			// Note: This conditional is only entered once per call
			h.lossTime = now.Add(delayUntilLost - timeSinceSent)
		}
		return true, nil
	})

	for _, p := range lostPackets {
		// the bytes in flight need to be reduced no matter if this packet will be retransmitted
		if p.includedInBytesInFlight {
			h.bytesInFlight -= p.Length
			h.congestion.OnPacketLost(p.PacketNumber, p.Length, priorInFlight)
		}
		if p.canBeRetransmitted {
			// queue the packet for retransmission, and report the loss to the congestion controller
			h.logger.Debugf("\tQueueing packet %#x because it was detected lost", p.PacketNumber)
			if err := h.queuePacketForRetransmission(p); err != nil {
				return err
			}
		}
		h.packetHistory.Remove(p.PacketNumber)
	}
	return nil
}

func (h *sentPacketHandler) OnAlarm() error {
	now := time.Now()

	// TODO(#497): TLP
	var err error
	if !h.handshakeComplete {
		h.handshakeCount++
		err = h.queueHandshakePacketsForRetransmission()
	} else if !h.lossTime.IsZero() {
		// Early retransmit or time loss detection
		err = h.detectLostPackets(now, h.bytesInFlight)
	} else {
		// RTO
		h.rtoCount++
		h.numRTOs += 2
		err = h.queueRTOs()
	}
	if err != nil {
		return err
	}
	h.updateLossDetectionAlarm()
	return nil
}

func (h *sentPacketHandler) GetAlarmTimeout() time.Time {
	return h.alarm
}

func (h *sentPacketHandler) onPacketAcked(p *Packet) error {
	// This happens if a packet and its retransmissions is acked in the same ACK.
	// As soon as we process the first one, this will remove all the retransmissions,
	// so we won't find the retransmitted packet number later.
	if packet := h.packetHistory.GetPacket(p.PacketNumber); packet == nil {
		return nil
	}

	// only report the acking of this packet to the congestion controller if:
	// * it is a retransmittable packet
	// * this packet wasn't retransmitted yet
	if p.isRetransmission {
		// that the parent doesn't exist is expected to happen every time the original packet was already acked
		if parent := h.packetHistory.GetPacket(p.retransmissionOf); parent != nil {
			if len(parent.retransmittedAs) == 1 {
				parent.retransmittedAs = nil
			} else {
				// remove this packet from the slice of retransmission
				retransmittedAs := make([]protocol.PacketNumber, 0, len(parent.retransmittedAs)-1)
				for _, pn := range parent.retransmittedAs {
					if pn != p.PacketNumber {
						retransmittedAs = append(retransmittedAs, pn)
					}
				}
				parent.retransmittedAs = retransmittedAs
			}
		}
	}
	// this also applies to packets that have been retransmitted as probe packets
	if p.includedInBytesInFlight {
		h.bytesInFlight -= p.Length
	}
	if h.rtoCount > 0 {
		h.verifyRTO(p.PacketNumber)
	}
	if err := h.stopRetransmissionsFor(p); err != nil {
		return err
	}
	h.rtoCount = 0
	h.handshakeCount = 0
	// TODO(#497): h.tlpCount = 0
	return h.packetHistory.Remove(p.PacketNumber)
}

func (h *sentPacketHandler) stopRetransmissionsFor(p *Packet) error {
	if err := h.packetHistory.MarkCannotBeRetransmitted(p.PacketNumber); err != nil {
		return err
	}
	for _, r := range p.retransmittedAs {
		packet := h.packetHistory.GetPacket(r)
		if packet == nil {
			return fmt.Errorf("sent packet handler BUG: marking packet as not retransmittable %d (retransmission of %d) not found in history", r, p.PacketNumber)
		}
		h.stopRetransmissionsFor(packet)
	}
	return nil
}

func (h *sentPacketHandler) verifyRTO(pn protocol.PacketNumber) {
	if pn <= h.largestSentBeforeRTO {
		h.logger.Debugf("Spurious RTO detected. Received an ACK for %#x (largest sent before RTO: %#x)", pn, h.largestSentBeforeRTO)
		// Replace SRTT with latest_rtt and increase the variance to prevent
		// a spurious RTO from happening again.
		h.rttStats.ExpireSmoothedMetrics()
		return
	}
	h.logger.Debugf("RTO verified. Received an ACK for %#x (largest sent before RTO: %#x", pn, h.largestSentBeforeRTO)
	h.congestion.OnRetransmissionTimeout(true)
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

func (h *sentPacketHandler) GetPacketNumberLen(p protocol.PacketNumber) protocol.PacketNumberLen {
	return protocol.GetPacketNumberLengthForHeader(p, h.lowestUnacked())
}

func (h *sentPacketHandler) GetStopWaitingFrame(force bool) *wire.StopWaitingFrame {
	return h.stopWaitingManager.GetStopWaitingFrame(force)
}

func (h *sentPacketHandler) SendMode() SendMode {
	numTrackedPackets := len(h.retransmissionQueue) + h.packetHistory.Len()

	// Don't send any packets if we're keeping track of the maximum number of packets.
	// Note that since MaxOutstandingSentPackets is smaller than MaxTrackedSentPackets,
	// we will stop sending out new data when reaching MaxOutstandingSentPackets,
	// but still allow sending of retransmissions and ACKs.
	if numTrackedPackets >= protocol.MaxTrackedSentPackets {
		h.logger.Debugf("Limited by the number of tracked packets: tracking %d packets, maximum %d", numTrackedPackets, protocol.MaxTrackedSentPackets)
		return SendNone
	}
	if h.numRTOs > 0 {
		return SendRTO
	}
	// Only send ACKs if we're congestion limited.
	if cwnd := h.congestion.GetCongestionWindow(); h.bytesInFlight > cwnd {
		h.logger.Debugf("Congestion limited: bytes in flight %d, window %d", h.bytesInFlight, cwnd)
		return SendAck
	}
	// Send retransmissions first, if there are any.
	if len(h.retransmissionQueue) > 0 {
		return SendRetransmission
	}
	if numTrackedPackets >= protocol.MaxOutstandingSentPackets {
		h.logger.Debugf("Max outstanding limited: tracking %d packets, maximum: %d", numTrackedPackets, protocol.MaxOutstandingSentPackets)
		return SendAck
	}
	return SendAny
}

func (h *sentPacketHandler) TimeUntilSend() time.Time {
	return h.nextPacketSendTime
}

func (h *sentPacketHandler) ShouldSendNumPackets() int {
	if h.numRTOs > 0 {
		// RTO probes should not be paced, but must be sent immediately.
		return h.numRTOs
	}
	delay := h.congestion.TimeUntilSend(h.bytesInFlight)
	if delay == 0 || delay > protocol.MinPacingDelay {
		return 1
	}
	return int(math.Ceil(float64(protocol.MinPacingDelay) / float64(delay)))
}

// retransmit the oldest two packets
func (h *sentPacketHandler) queueRTOs() error {
	h.largestSentBeforeRTO = h.lastSentPacketNumber
	// Queue the first two outstanding packets for retransmission.
	// This does NOT declare this packets as lost:
	// They are still tracked in the packet history and count towards the bytes in flight.
	for i := 0; i < 2; i++ {
		if p := h.packetHistory.FirstOutstanding(); p != nil {
			h.logger.Debugf("\tQueueing packet %#x for retransmission (RTO)", p.PacketNumber)
			if err := h.queuePacketForRetransmission(p); err != nil {
				return err
			}
		}
	}
	return nil
}

func (h *sentPacketHandler) queueHandshakePacketsForRetransmission() error {
	var handshakePackets []*Packet
	h.packetHistory.Iterate(func(p *Packet) (bool, error) {
		if p.canBeRetransmitted && p.EncryptionLevel < protocol.EncryptionForwardSecure {
			handshakePackets = append(handshakePackets, p)
		}
		return true, nil
	})
	for _, p := range handshakePackets {
		h.logger.Debugf("\tQueueing packet %#x as a handshake retransmission", p.PacketNumber)
		if err := h.queuePacketForRetransmission(p); err != nil {
			return err
		}
	}
	return nil
}

func (h *sentPacketHandler) queuePacketForRetransmission(p *Packet) error {
	if !p.canBeRetransmitted {
		return fmt.Errorf("sent packet handler BUG: packet %d already queued for retransmission", p.PacketNumber)
	}
	if err := h.packetHistory.MarkCannotBeRetransmitted(p.PacketNumber); err != nil {
		return err
	}
	h.retransmissionQueue = append(h.retransmissionQueue, p)
	h.stopWaitingManager.QueuedRetransmissionForPacketNumber(p.PacketNumber)
	return nil
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
	var rto time.Duration
	rtt := h.rttStats.SmoothedRTT()
	if rtt == 0 {
		rto = defaultRTOTimeout
	} else {
		rto = rtt + 4*h.rttStats.MeanDeviation()
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
