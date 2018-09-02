package wire

import (
	"bytes"
	"errors"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

var errInvalidAckRanges = errors.New("AckFrame: ACK frame contains invalid ACK ranges")

func parseAckFrameLegacy(r *bytes.Reader, _ protocol.VersionNumber) (*AckFrame, error) {
	frame := &AckFrame{}

	typeByte, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	hasMissingRanges := typeByte&0x20 == 0x20
	largestAckedLen := 2 * ((typeByte & 0x0C) >> 2)
	if largestAckedLen == 0 {
		largestAckedLen = 1
	}

	missingSequenceNumberDeltaLen := 2 * (typeByte & 0x03)
	if missingSequenceNumberDeltaLen == 0 {
		missingSequenceNumberDeltaLen = 1
	}

	la, err := utils.BigEndian.ReadUintN(r, largestAckedLen)
	if err != nil {
		return nil, err
	}
	largestAcked := protocol.PacketNumber(la)

	delay, err := utils.BigEndian.ReadUfloat16(r)
	if err != nil {
		return nil, err
	}
	frame.DelayTime = time.Duration(delay) * time.Microsecond

	var numAckBlocks uint8
	if hasMissingRanges {
		numAckBlocks, err = r.ReadByte()
		if err != nil {
			return nil, err
		}
	}

	if hasMissingRanges && numAckBlocks == 0 {
		return nil, errInvalidAckRanges
	}

	abl, err := utils.BigEndian.ReadUintN(r, missingSequenceNumberDeltaLen)
	if err != nil {
		return nil, err
	}
	ackBlockLength := protocol.PacketNumber(abl)
	if largestAcked > 0 && ackBlockLength < 1 {
		return nil, errors.New("invalid first ACK range")
	}

	if ackBlockLength > largestAcked+1 {
		return nil, errInvalidAckRanges
	}

	if hasMissingRanges {
		ackRange := AckRange{
			Smallest: largestAcked - ackBlockLength + 1,
			Largest:  largestAcked,
		}
		frame.AckRanges = append(frame.AckRanges, ackRange)

		var inLongBlock bool
		var lastRangeComplete bool
		for i := uint8(0); i < numAckBlocks; i++ {
			var gap uint8
			gap, err = r.ReadByte()
			if err != nil {
				return nil, err
			}

			abl, err := utils.BigEndian.ReadUintN(r, missingSequenceNumberDeltaLen)
			if err != nil {
				return nil, err
			}
			ackBlockLength := protocol.PacketNumber(abl)

			if inLongBlock {
				frame.AckRanges[len(frame.AckRanges)-1].Smallest -= protocol.PacketNumber(gap) + ackBlockLength
				frame.AckRanges[len(frame.AckRanges)-1].Largest -= protocol.PacketNumber(gap)
			} else {
				lastRangeComplete = false
				ackRange := AckRange{
					Largest: frame.AckRanges[len(frame.AckRanges)-1].Smallest - protocol.PacketNumber(gap) - 1,
				}
				ackRange.Smallest = ackRange.Largest - ackBlockLength + 1
				frame.AckRanges = append(frame.AckRanges, ackRange)
			}

			if ackBlockLength > 0 {
				lastRangeComplete = true
			}
			inLongBlock = (ackBlockLength == 0)
		}

		// if the last range was not complete, First and Last make no sense
		// remove the range from frame.AckRanges
		if !lastRangeComplete {
			frame.AckRanges = frame.AckRanges[:len(frame.AckRanges)-1]
		}
	} else {
		frame.AckRanges = make([]AckRange, 1)
		if largestAcked != 0 {
			frame.AckRanges[0].Largest = largestAcked
			frame.AckRanges[0].Smallest = largestAcked + 1 - ackBlockLength
		}
	}

	if !frame.validateAckRanges() {
		return nil, errInvalidAckRanges
	}

	var numTimestamp byte
	numTimestamp, err = r.ReadByte()
	if err != nil {
		return nil, err
	}

	if numTimestamp > 0 {
		// Delta Largest acked
		_, err = r.ReadByte()
		if err != nil {
			return nil, err
		}
		// First Timestamp
		_, err = utils.BigEndian.ReadUint32(r)
		if err != nil {
			return nil, err
		}

		for i := 0; i < int(numTimestamp)-1; i++ {
			// Delta Largest acked
			_, err = r.ReadByte()
			if err != nil {
				return nil, err
			}

			// Time Since Previous Timestamp
			_, err = utils.BigEndian.ReadUint16(r)
			if err != nil {
				return nil, err
			}
		}
	}
	return frame, nil
}

func (f *AckFrame) writeLegacy(b *bytes.Buffer, _ protocol.VersionNumber) error {
	largestAcked := f.LargestAcked()
	largestAckedLen := protocol.GetPacketNumberLength(largestAcked)

	typeByte := uint8(0x40)

	if largestAckedLen != protocol.PacketNumberLen1 {
		typeByte ^= (uint8(largestAckedLen / 2)) << 2
	}

	missingSequenceNumberDeltaLen := f.getMissingSequenceNumberDeltaLen()
	if missingSequenceNumberDeltaLen != protocol.PacketNumberLen1 {
		typeByte ^= (uint8(missingSequenceNumberDeltaLen / 2))
	}

	if f.HasMissingRanges() {
		typeByte |= 0x20
	}

	b.WriteByte(typeByte)

	switch largestAckedLen {
	case protocol.PacketNumberLen1:
		b.WriteByte(uint8(largestAcked))
	case protocol.PacketNumberLen2:
		utils.BigEndian.WriteUint16(b, uint16(largestAcked))
	case protocol.PacketNumberLen4:
		utils.BigEndian.WriteUint32(b, uint32(largestAcked))
	case protocol.PacketNumberLen6:
		utils.BigEndian.WriteUint48(b, uint64(largestAcked)&(1<<48-1))
	}

	utils.BigEndian.WriteUfloat16(b, uint64(f.DelayTime/time.Microsecond))

	var numRanges uint64
	var numRangesWritten uint64
	if f.HasMissingRanges() {
		numRanges = f.numWritableNackRanges()
		if numRanges > 0xFF {
			panic("AckFrame: Too many ACK ranges")
		}
		b.WriteByte(uint8(numRanges - 1))
	}

	var firstAckBlockLength protocol.PacketNumber
	if !f.HasMissingRanges() {
		firstAckBlockLength = largestAcked - f.LowestAcked() + 1
	} else {
		firstAckBlockLength = largestAcked - f.AckRanges[0].Smallest + 1
		numRangesWritten++
	}

	switch missingSequenceNumberDeltaLen {
	case protocol.PacketNumberLen1:
		b.WriteByte(uint8(firstAckBlockLength))
	case protocol.PacketNumberLen2:
		utils.BigEndian.WriteUint16(b, uint16(firstAckBlockLength))
	case protocol.PacketNumberLen4:
		utils.BigEndian.WriteUint32(b, uint32(firstAckBlockLength))
	case protocol.PacketNumberLen6:
		utils.BigEndian.WriteUint48(b, uint64(firstAckBlockLength)&(1<<48-1))
	}

	for i, ackRange := range f.AckRanges {
		if i == 0 {
			continue
		}

		length := ackRange.Largest - ackRange.Smallest + 1
		gap := f.AckRanges[i-1].Smallest - ackRange.Largest - 1

		num := gap/0xFF + 1
		if gap%0xFF == 0 {
			num--
		}

		if num == 1 {
			b.WriteByte(uint8(gap))
			switch missingSequenceNumberDeltaLen {
			case protocol.PacketNumberLen1:
				b.WriteByte(uint8(length))
			case protocol.PacketNumberLen2:
				utils.BigEndian.WriteUint16(b, uint16(length))
			case protocol.PacketNumberLen4:
				utils.BigEndian.WriteUint32(b, uint32(length))
			case protocol.PacketNumberLen6:
				utils.BigEndian.WriteUint48(b, uint64(length)&(1<<48-1))
			}
			numRangesWritten++
		} else {
			for i := 0; i < int(num); i++ {
				var lengthWritten uint64
				var gapWritten uint8

				if i == int(num)-1 { // last block
					lengthWritten = uint64(length)
					gapWritten = uint8(1 + ((gap - 1) % 255))
				} else {
					lengthWritten = 0
					gapWritten = 0xFF
				}

				b.WriteByte(gapWritten)
				switch missingSequenceNumberDeltaLen {
				case protocol.PacketNumberLen1:
					b.WriteByte(uint8(lengthWritten))
				case protocol.PacketNumberLen2:
					utils.BigEndian.WriteUint16(b, uint16(lengthWritten))
				case protocol.PacketNumberLen4:
					utils.BigEndian.WriteUint32(b, uint32(lengthWritten))
				case protocol.PacketNumberLen6:
					utils.BigEndian.WriteUint48(b, lengthWritten&(1<<48-1))
				}

				numRangesWritten++
			}
		}

		// this is needed if not all AckRanges can be written to the ACK frame (if there are more than 0xFF)
		if numRangesWritten >= numRanges {
			break
		}
	}

	if numRanges != numRangesWritten {
		return errors.New("BUG: Inconsistent number of ACK ranges written")
	}

	b.WriteByte(0) // no timestamps
	return nil
}

func (f *AckFrame) lengthLegacy(_ protocol.VersionNumber) protocol.ByteCount {
	length := protocol.ByteCount(1 + 2 + 1) // 1 TypeByte, 2 ACK delay time, 1 Num Timestamp
	length += protocol.ByteCount(protocol.GetPacketNumberLength(f.LargestAcked()))

	missingSequenceNumberDeltaLen := protocol.ByteCount(f.getMissingSequenceNumberDeltaLen())

	if f.HasMissingRanges() {
		length += (1 + missingSequenceNumberDeltaLen) * protocol.ByteCount(f.numWritableNackRanges())
	} else {
		length += missingSequenceNumberDeltaLen
	}
	// we don't write
	return length
}

// numWritableNackRanges calculates the number of ACK blocks that are about to be written
// this number is different from len(f.AckRanges) for the case of long gaps (> 255 packets)
func (f *AckFrame) numWritableNackRanges() uint64 {
	if len(f.AckRanges) == 0 {
		return 0
	}

	var numRanges uint64
	for i, ackRange := range f.AckRanges {
		if i == 0 {
			continue
		}

		lastAckRange := f.AckRanges[i-1]
		gap := lastAckRange.Smallest - ackRange.Largest - 1
		rangeLength := 1 + uint64(gap)/0xFF
		if uint64(gap)%0xFF == 0 {
			rangeLength--
		}

		if numRanges+rangeLength < 0xFF {
			numRanges += rangeLength
		} else {
			break
		}
	}

	return numRanges + 1
}

func (f *AckFrame) getMissingSequenceNumberDeltaLen() protocol.PacketNumberLen {
	var maxRangeLength protocol.PacketNumber

	if f.HasMissingRanges() {
		for _, ackRange := range f.AckRanges {
			rangeLength := ackRange.Largest - ackRange.Smallest + 1
			if rangeLength > maxRangeLength {
				maxRangeLength = rangeLength
			}
		}
	} else {
		maxRangeLength = f.LargestAcked() - f.LowestAcked() + 1
	}

	if maxRangeLength <= 0xFF {
		return protocol.PacketNumberLen1
	}
	if maxRangeLength <= 0xFFFF {
		return protocol.PacketNumberLen2
	}
	if maxRangeLength <= 0xFFFFFFFF {
		return protocol.PacketNumberLen4
	}

	return protocol.PacketNumberLen6
}
