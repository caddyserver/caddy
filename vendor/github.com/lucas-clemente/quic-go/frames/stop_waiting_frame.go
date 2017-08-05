package frames

import (
	"bytes"
	"errors"

	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
)

// A StopWaitingFrame in QUIC
type StopWaitingFrame struct {
	LeastUnacked    protocol.PacketNumber
	PacketNumberLen protocol.PacketNumberLen
	PacketNumber    protocol.PacketNumber
}

var (
	errLeastUnackedHigherThanPacketNumber = errors.New("StopWaitingFrame: LeastUnacked can't be greater than the packet number")
	errPacketNumberNotSet                 = errors.New("StopWaitingFrame: PacketNumber not set")
	errPacketNumberLenNotSet              = errors.New("StopWaitingFrame: PacketNumberLen not set")
)

func (f *StopWaitingFrame) Write(b *bytes.Buffer, version protocol.VersionNumber) error {
	// packetNumber is the packet number of the packet that this StopWaitingFrame will be sent with
	typeByte := uint8(0x06)
	b.WriteByte(typeByte)

	// make sure the PacketNumber was set
	if f.PacketNumber == protocol.PacketNumber(0) {
		return errPacketNumberNotSet
	}

	if f.LeastUnacked > f.PacketNumber {
		return errLeastUnackedHigherThanPacketNumber
	}

	leastUnackedDelta := uint64(f.PacketNumber - f.LeastUnacked)

	switch f.PacketNumberLen {
	case protocol.PacketNumberLen1:
		b.WriteByte(uint8(leastUnackedDelta))
	case protocol.PacketNumberLen2:
		utils.WriteUint16(b, uint16(leastUnackedDelta))
	case protocol.PacketNumberLen4:
		utils.WriteUint32(b, uint32(leastUnackedDelta))
	case protocol.PacketNumberLen6:
		utils.WriteUint48(b, leastUnackedDelta)
	default:
		return errPacketNumberLenNotSet
	}

	return nil
}

// MinLength of a written frame
func (f *StopWaitingFrame) MinLength(version protocol.VersionNumber) (protocol.ByteCount, error) {
	minLength := protocol.ByteCount(1) // typeByte

	if f.PacketNumberLen == protocol.PacketNumberLenInvalid {
		return 0, errPacketNumberLenNotSet
	}
	minLength += protocol.ByteCount(f.PacketNumberLen)

	return minLength, nil
}

// ParseStopWaitingFrame parses a StopWaiting frame
func ParseStopWaitingFrame(r *bytes.Reader, packetNumber protocol.PacketNumber, packetNumberLen protocol.PacketNumberLen, version protocol.VersionNumber) (*StopWaitingFrame, error) {
	frame := &StopWaitingFrame{}

	// read the TypeByte
	_, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	leastUnackedDelta, err := utils.ReadUintN(r, uint8(packetNumberLen))
	if err != nil {
		return nil, err
	}

	if leastUnackedDelta > uint64(packetNumber) {
		return nil, qerr.Error(qerr.InvalidStopWaitingData, "invalid LeastUnackedDelta")
	}

	frame.LeastUnacked = protocol.PacketNumber(uint64(packetNumber) - leastUnackedDelta)

	return frame, nil
}
