package ackhandler

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"github.com/lucas-clemente/quic-go/qerr"
)

// The receivedPacketHistory stores if a packet number has already been received.
// It does not store packet contents.
type receivedPacketHistory struct {
	ranges *utils.PacketIntervalList

	lowestInReceivedPacketNumbers protocol.PacketNumber
}

var errTooManyOutstandingReceivedAckRanges = qerr.Error(qerr.TooManyOutstandingReceivedPackets, "Too many outstanding received ACK ranges")

// newReceivedPacketHistory creates a new received packet history
func newReceivedPacketHistory() *receivedPacketHistory {
	return &receivedPacketHistory{
		ranges: utils.NewPacketIntervalList(),
	}
}

// ReceivedPacket registers a packet with PacketNumber p and updates the ranges
func (h *receivedPacketHistory) ReceivedPacket(p protocol.PacketNumber) error {
	if h.ranges.Len() >= protocol.MaxTrackedReceivedAckRanges {
		return errTooManyOutstandingReceivedAckRanges
	}

	if h.ranges.Len() == 0 {
		h.ranges.PushBack(utils.PacketInterval{Start: p, End: p})
		return nil
	}

	for el := h.ranges.Back(); el != nil; el = el.Prev() {
		// p already included in an existing range. Nothing to do here
		if p >= el.Value.Start && p <= el.Value.End {
			return nil
		}

		var rangeExtended bool
		if el.Value.End == p-1 { // extend a range at the end
			rangeExtended = true
			el.Value.End = p
		} else if el.Value.Start == p+1 { // extend a range at the beginning
			rangeExtended = true
			el.Value.Start = p
		}

		// if a range was extended (either at the beginning or at the end, maybe it is possible to merge two ranges into one)
		if rangeExtended {
			prev := el.Prev()
			if prev != nil && prev.Value.End+1 == el.Value.Start { // merge two ranges
				prev.Value.End = el.Value.End
				h.ranges.Remove(el)
				return nil
			}
			return nil // if the two ranges were not merge, we're done here
		}

		// create a new range at the end
		if p > el.Value.End {
			h.ranges.InsertAfter(utils.PacketInterval{Start: p, End: p}, el)
			return nil
		}
	}

	// create a new range at the beginning
	h.ranges.InsertBefore(utils.PacketInterval{Start: p, End: p}, h.ranges.Front())

	return nil
}

// DeleteBelow deletes all entries below (but not including) p
func (h *receivedPacketHistory) DeleteBelow(p protocol.PacketNumber) {
	if p <= h.lowestInReceivedPacketNumbers {
		return
	}
	h.lowestInReceivedPacketNumbers = p

	nextEl := h.ranges.Front()
	for el := h.ranges.Front(); nextEl != nil; el = nextEl {
		nextEl = el.Next()

		if p > el.Value.Start && p <= el.Value.End {
			el.Value.Start = p
		} else if el.Value.End < p { // delete a whole range
			h.ranges.Remove(el)
		} else { // no ranges affected. Nothing to do
			return
		}
	}
}

// GetAckRanges gets a slice of all AckRanges that can be used in an AckFrame
func (h *receivedPacketHistory) GetAckRanges() []wire.AckRange {
	if h.ranges.Len() == 0 {
		return nil
	}

	ackRanges := make([]wire.AckRange, h.ranges.Len())
	i := 0
	for el := h.ranges.Back(); el != nil; el = el.Prev() {
		ackRanges[i] = wire.AckRange{First: el.Value.Start, Last: el.Value.End}
		i++
	}
	return ackRanges
}

func (h *receivedPacketHistory) GetHighestAckRange() wire.AckRange {
	ackRange := wire.AckRange{}
	if h.ranges.Len() > 0 {
		r := h.ranges.Back().Value
		ackRange.First = r.Start
		ackRange.Last = r.End
	}
	return ackRange
}
