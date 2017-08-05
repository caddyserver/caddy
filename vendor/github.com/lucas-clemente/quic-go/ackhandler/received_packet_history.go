package ackhandler

import (
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
)

type receivedPacketHistory struct {
	ranges *utils.PacketIntervalList

	// the map is used as a replacement for a set here. The bool is always supposed to be set to true
	receivedPacketNumbers         map[protocol.PacketNumber]bool
	lowestInReceivedPacketNumbers protocol.PacketNumber
}

var (
	errTooManyOutstandingReceivedAckRanges = qerr.Error(qerr.TooManyOutstandingReceivedPackets, "Too many outstanding received ACK ranges")
	errTooManyOutstandingReceivedPackets   = qerr.Error(qerr.TooManyOutstandingReceivedPackets, "Too many outstanding received packets")
)

// newReceivedPacketHistory creates a new received packet history
func newReceivedPacketHistory() *receivedPacketHistory {
	return &receivedPacketHistory{
		ranges:                utils.NewPacketIntervalList(),
		receivedPacketNumbers: make(map[protocol.PacketNumber]bool),
	}
}

// ReceivedPacket registers a packet with PacketNumber p and updates the ranges
func (h *receivedPacketHistory) ReceivedPacket(p protocol.PacketNumber) error {
	if h.ranges.Len() >= protocol.MaxTrackedReceivedAckRanges {
		return errTooManyOutstandingReceivedAckRanges
	}

	if len(h.receivedPacketNumbers) >= protocol.MaxTrackedReceivedPackets {
		return errTooManyOutstandingReceivedPackets
	}

	h.receivedPacketNumbers[p] = true

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

// DeleteBelow deletes all entries below the leastUnacked packet number
func (h *receivedPacketHistory) DeleteBelow(leastUnacked protocol.PacketNumber) {
	h.lowestInReceivedPacketNumbers = utils.MaxPacketNumber(h.lowestInReceivedPacketNumbers, leastUnacked)

	nextEl := h.ranges.Front()
	for el := h.ranges.Front(); nextEl != nil; el = nextEl {
		nextEl = el.Next()

		if leastUnacked > el.Value.Start && leastUnacked <= el.Value.End {
			for i := el.Value.Start; i < leastUnacked; i++ { // adjust start value of a range
				delete(h.receivedPacketNumbers, i)
			}
			el.Value.Start = leastUnacked
		} else if el.Value.End < leastUnacked { // delete a whole range
			for i := el.Value.Start; i <= el.Value.End; i++ {
				delete(h.receivedPacketNumbers, i)
			}
			h.ranges.Remove(el)
		} else { // no ranges affected. Nothing to do
			return
		}
	}
}

// IsDuplicate determines if a packet should be regarded as a duplicate packet
// note that after receiving a StopWaitingFrame, all packets below the LeastUnacked should be regarded as duplicates, even if the packet was just delayed
func (h *receivedPacketHistory) IsDuplicate(p protocol.PacketNumber) bool {
	if p < h.lowestInReceivedPacketNumbers {
		return true
	}

	_, ok := h.receivedPacketNumbers[p]
	return ok
}

// GetAckRanges gets a slice of all AckRanges that can be used in an AckFrame
func (h *receivedPacketHistory) GetAckRanges() []frames.AckRange {
	if h.ranges.Len() == 0 {
		return nil
	}

	var ackRanges []frames.AckRange

	for el := h.ranges.Back(); el != nil; el = el.Prev() {
		ackRanges = append(ackRanges, frames.AckRange{FirstPacketNumber: el.Value.Start, LastPacketNumber: el.Value.End})
	}

	return ackRanges
}

func (h *receivedPacketHistory) GetHighestAckRange() frames.AckRange {
	ackRange := frames.AckRange{}
	if h.ranges.Len() > 0 {
		r := h.ranges.Back().Value
		ackRange.FirstPacketNumber = r.Start
		ackRange.LastPacketNumber = r.End
	}
	return ackRange
}
