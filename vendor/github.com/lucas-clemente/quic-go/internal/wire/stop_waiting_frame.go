package wire

import (
	"bytes"
	"errors"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

// A StopWaitingFrame in QUIC
type StopWaitingFrame struct {
	LeastUnacked    protocol.PacketNumber
	PacketNumberLen protocol.PacketNumberLen
	// PacketNumber is the packet number of the packet that this StopWaitingFrame will be sent with
	PacketNumber protocol.PacketNumber
}

var (
	errLeastUnackedHigherThanPacketNumber = errors.New("StopWaitingFrame: LeastUnacked can't be greater than the packet number")
	errPacketNumberNotSet                 = errors.New("StopWaitingFrame: PacketNumber not set")
	errPacketNumberLenNotSet              = errors.New("StopWaitingFrame: PacketNumberLen not set")
)

func (f *StopWaitingFrame) Write(b *bytes.Buffer, v protocol.VersionNumber) error {
	if v.UsesIETFFrameFormat() {
		return errors.New("STOP_WAITING not defined in IETF QUIC")
	}
	// make sure the PacketNumber was set
	if f.PacketNumber == protocol.PacketNumber(0) {
		return errPacketNumberNotSet
	}
	if f.LeastUnacked > f.PacketNumber {
		return errLeastUnackedHigherThanPacketNumber
	}

	b.WriteByte(0x06)
	leastUnackedDelta := uint64(f.PacketNumber - f.LeastUnacked)
	switch f.PacketNumberLen {
	case protocol.PacketNumberLen1:
		b.WriteByte(uint8(leastUnackedDelta))
	case protocol.PacketNumberLen2:
		utils.BigEndian.WriteUint16(b, uint16(leastUnackedDelta))
	case protocol.PacketNumberLen4:
		utils.BigEndian.WriteUint32(b, uint32(leastUnackedDelta))
	case protocol.PacketNumberLen6:
		utils.BigEndian.WriteUint48(b, leastUnackedDelta&(1<<48-1))
	default:
		return errPacketNumberLenNotSet
	}
	return nil
}

// Length of a written frame
func (f *StopWaitingFrame) Length(_ protocol.VersionNumber) protocol.ByteCount {
	return 1 + protocol.ByteCount(f.PacketNumberLen)
}

// parseStopWaitingFrame parses a StopWaiting frame
func parseStopWaitingFrame(r *bytes.Reader, packetNumber protocol.PacketNumber, packetNumberLen protocol.PacketNumberLen, _ protocol.VersionNumber) (*StopWaitingFrame, error) {
	frame := &StopWaitingFrame{}

	// read the TypeByte
	if _, err := r.ReadByte(); err != nil {
		return nil, err
	}

	leastUnackedDelta, err := utils.BigEndian.ReadUintN(r, uint8(packetNumberLen))
	if err != nil {
		return nil, err
	}
	if leastUnackedDelta > uint64(packetNumber) {
		return nil, errors.New("invalid LeastUnackedDelta")
	}
	frame.LeastUnacked = protocol.PacketNumber(uint64(packetNumber) - leastUnackedDelta)
	return frame, nil
}
