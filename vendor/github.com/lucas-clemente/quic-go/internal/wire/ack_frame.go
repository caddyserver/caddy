package wire

import (
	"bytes"
	"errors"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

// TODO: use the value sent in the transport parameters
const ackDelayExponent = 3

// An AckFrame is an ACK frame
type AckFrame struct {
	LargestAcked protocol.PacketNumber
	LowestAcked  protocol.PacketNumber
	AckRanges    []AckRange // has to be ordered. The highest ACK range goes first, the lowest ACK range goes last

	// time when the LargestAcked was receiveid
	// this field will not be set for received ACKs frames
	PacketReceivedTime time.Time
	DelayTime          time.Duration
}

// ParseAckFrame reads an ACK frame
func ParseAckFrame(r *bytes.Reader, version protocol.VersionNumber) (*AckFrame, error) {
	if !version.UsesIETFFrameFormat() {
		return parseAckFrameLegacy(r, version)
	}

	if _, err := r.ReadByte(); err != nil {
		return nil, err
	}

	frame := &AckFrame{}

	largestAcked, err := utils.ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	frame.LargestAcked = protocol.PacketNumber(largestAcked)
	delay, err := utils.ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	frame.DelayTime = time.Duration(delay*1<<ackDelayExponent) * time.Microsecond
	numBlocks, err := utils.ReadVarInt(r)
	if err != nil {
		return nil, err
	}

	// read the first ACK range
	ab, err := utils.ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	ackBlock := protocol.PacketNumber(ab)
	if ackBlock > frame.LargestAcked {
		return nil, errors.New("invalid first ACK range")
	}
	smallest := frame.LargestAcked - protocol.PacketNumber(ackBlock)

	// read all the other ACK ranges
	if numBlocks > 0 {
		frame.AckRanges = append(frame.AckRanges, AckRange{First: smallest, Last: frame.LargestAcked})
	}
	for i := uint64(0); i < numBlocks; i++ {
		g, err := utils.ReadVarInt(r)
		if err != nil {
			return nil, err
		}
		gap := protocol.PacketNumber(g)
		if smallest < gap+2 {
			return nil, errInvalidAckRanges
		}
		largest := smallest - gap - 2

		ab, err := utils.ReadVarInt(r)
		if err != nil {
			return nil, err
		}
		ackBlock := protocol.PacketNumber(ab)

		if ackBlock > largest {
			return nil, errInvalidAckRanges
		}
		smallest = largest - protocol.PacketNumber(ackBlock)
		frame.AckRanges = append(frame.AckRanges, AckRange{First: smallest, Last: largest})
	}

	frame.LowestAcked = smallest
	if !frame.validateAckRanges() {
		return nil, errInvalidAckRanges
	}

	return frame, nil
}

// Write writes an ACK frame.
func (f *AckFrame) Write(b *bytes.Buffer, version protocol.VersionNumber) error {
	if !version.UsesIETFFrameFormat() {
		return f.writeLegacy(b, version)
	}

	b.WriteByte(0xe)
	utils.WriteVarInt(b, uint64(f.LargestAcked))
	utils.WriteVarInt(b, encodeAckDelay(f.DelayTime))

	// TODO: limit the number of ACK ranges, such that the frame doesn't grow larger than an upper bound
	var lowestInFirstRange protocol.PacketNumber
	if f.HasMissingRanges() {
		utils.WriteVarInt(b, uint64(len(f.AckRanges)-1))
		lowestInFirstRange = f.AckRanges[0].First
	} else {
		utils.WriteVarInt(b, 0)
		lowestInFirstRange = f.LowestAcked
	}

	// write the first range
	utils.WriteVarInt(b, uint64(f.LargestAcked-lowestInFirstRange))

	// write all the other range
	if !f.HasMissingRanges() {
		return nil
	}
	var lowest protocol.PacketNumber
	for i, ackRange := range f.AckRanges {
		if i == 0 {
			lowest = lowestInFirstRange
			continue
		}
		utils.WriteVarInt(b, uint64(lowest-ackRange.Last-2))
		utils.WriteVarInt(b, uint64(ackRange.Last-ackRange.First))
		lowest = ackRange.First
	}
	return nil
}

// MinLength of a written frame
func (f *AckFrame) MinLength(version protocol.VersionNumber) protocol.ByteCount {
	if !version.UsesIETFFrameFormat() {
		return f.minLengthLegacy(version)
	}

	length := 1 + utils.VarIntLen(uint64(f.LargestAcked)) + utils.VarIntLen(uint64(encodeAckDelay(f.DelayTime)))

	var lowestInFirstRange protocol.PacketNumber
	if f.HasMissingRanges() {
		length += utils.VarIntLen(uint64(len(f.AckRanges) - 1))
		lowestInFirstRange = f.AckRanges[0].First
	} else {
		length += utils.VarIntLen(0)
		lowestInFirstRange = f.LowestAcked
	}
	length += utils.VarIntLen(uint64(f.LargestAcked - lowestInFirstRange))

	if !f.HasMissingRanges() {
		return length
	}
	var lowest protocol.PacketNumber
	for i, ackRange := range f.AckRanges {
		if i == 0 {
			lowest = ackRange.First
			continue
		}
		length += utils.VarIntLen(uint64(lowest - ackRange.Last - 2))
		length += utils.VarIntLen(uint64(ackRange.Last - ackRange.First))
		lowest = ackRange.First
	}
	return length
}

// HasMissingRanges returns if this frame reports any missing packets
func (f *AckFrame) HasMissingRanges() bool {
	return len(f.AckRanges) > 0
}

func (f *AckFrame) validateAckRanges() bool {
	if len(f.AckRanges) == 0 {
		return true
	}

	// if there are missing packets, there will always be at least 2 ACK ranges
	if len(f.AckRanges) == 1 {
		return false
	}

	if f.AckRanges[0].Last != f.LargestAcked {
		return false
	}

	// check the validity of every single ACK range
	for _, ackRange := range f.AckRanges {
		if ackRange.First > ackRange.Last {
			return false
		}
	}

	// check the consistency for ACK with multiple NACK ranges
	for i, ackRange := range f.AckRanges {
		if i == 0 {
			continue
		}
		lastAckRange := f.AckRanges[i-1]
		if lastAckRange.First <= ackRange.First {
			return false
		}
		if lastAckRange.First <= ackRange.Last+1 {
			return false
		}
	}

	return true
}

// AcksPacket determines if this ACK frame acks a certain packet number
func (f *AckFrame) AcksPacket(p protocol.PacketNumber) bool {
	if p < f.LowestAcked || p > f.LargestAcked { // this is just a performance optimization
		return false
	}

	if f.HasMissingRanges() {
		// TODO: this could be implemented as a binary search
		for _, ackRange := range f.AckRanges {
			if p >= ackRange.First && p <= ackRange.Last {
				return true
			}
		}
		return false
	}
	// if packet doesn't have missing ranges
	return (p >= f.LowestAcked && p <= f.LargestAcked)
}

func encodeAckDelay(delay time.Duration) uint64 {
	return uint64(delay.Nanoseconds() / (1000 * (1 << ackDelayExponent)))
}
