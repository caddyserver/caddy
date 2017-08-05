package frames

import (
	"bytes"
	"errors"

	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
)

// A StreamFrame of QUIC
type StreamFrame struct {
	StreamID       protocol.StreamID
	FinBit         bool
	DataLenPresent bool
	Offset         protocol.ByteCount
	Data           []byte
}

var (
	errInvalidStreamIDLen = errors.New("StreamFrame: Invalid StreamID length")
	errInvalidOffsetLen   = errors.New("StreamFrame: Invalid offset length")
)

// ParseStreamFrame reads a stream frame. The type byte must not have been read yet.
func ParseStreamFrame(r *bytes.Reader) (*StreamFrame, error) {
	frame := &StreamFrame{}

	typeByte, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	frame.FinBit = typeByte&0x40 > 0
	frame.DataLenPresent = typeByte&0x20 > 0
	offsetLen := typeByte & 0x1C >> 2
	if offsetLen != 0 {
		offsetLen++
	}
	streamIDLen := typeByte&0x03 + 1

	sid, err := utils.ReadUintN(r, streamIDLen)
	if err != nil {
		return nil, err
	}
	frame.StreamID = protocol.StreamID(sid)

	offset, err := utils.ReadUintN(r, offsetLen)
	if err != nil {
		return nil, err
	}
	frame.Offset = protocol.ByteCount(offset)

	var dataLen uint16
	if frame.DataLenPresent {
		dataLen, err = utils.ReadUint16(r)
		if err != nil {
			return nil, err
		}
	}

	if dataLen > uint16(protocol.MaxPacketSize) {
		return nil, qerr.Error(qerr.InvalidStreamData, "data len too large")
	}

	if !frame.DataLenPresent {
		// The rest of the packet is data
		dataLen = uint16(r.Len())
	}
	if dataLen != 0 {
		frame.Data = make([]byte, dataLen)
		n, err := r.Read(frame.Data)
		if n != int(dataLen) {
			return nil, errors.New("BUG: StreamFrame could not read dataLen bytes")
		}
		if err != nil {
			return nil, err
		}
	}

	if frame.Offset+frame.DataLen() < frame.Offset {
		return nil, qerr.Error(qerr.InvalidStreamData, "data overflows maximum offset")
	}

	if !frame.FinBit && frame.DataLen() == 0 {
		return nil, qerr.EmptyStreamFrameNoFin
	}

	return frame, nil
}

// WriteStreamFrame writes a stream frame.
func (f *StreamFrame) Write(b *bytes.Buffer, version protocol.VersionNumber) error {
	if len(f.Data) == 0 && !f.FinBit {
		return errors.New("StreamFrame: attempting to write empty frame without FIN")
	}

	typeByte := uint8(0x80) // sets the leftmost bit to 1

	if f.FinBit {
		typeByte ^= 0x40
	}

	if f.DataLenPresent {
		typeByte ^= 0x20
	}

	offsetLength := f.getOffsetLength()

	if offsetLength > 0 {
		typeByte ^= (uint8(offsetLength) - 1) << 2
	}

	streamIDLen := f.calculateStreamIDLength()
	typeByte ^= streamIDLen - 1

	b.WriteByte(typeByte)

	switch streamIDLen {
	case 1:
		b.WriteByte(uint8(f.StreamID))
	case 2:
		utils.WriteUint16(b, uint16(f.StreamID))
	case 3:
		utils.WriteUint24(b, uint32(f.StreamID))
	case 4:
		utils.WriteUint32(b, uint32(f.StreamID))
	default:
		return errInvalidStreamIDLen
	}

	switch offsetLength {
	case 0:
	case 2:
		utils.WriteUint16(b, uint16(f.Offset))
	case 3:
		utils.WriteUint24(b, uint32(f.Offset))
	case 4:
		utils.WriteUint32(b, uint32(f.Offset))
	case 5:
		utils.WriteUint40(b, uint64(f.Offset))
	case 6:
		utils.WriteUint48(b, uint64(f.Offset))
	case 7:
		utils.WriteUint56(b, uint64(f.Offset))
	case 8:
		utils.WriteUint64(b, uint64(f.Offset))
	default:
		return errInvalidOffsetLen
	}

	if f.DataLenPresent {
		utils.WriteUint16(b, uint16(len(f.Data)))
	}

	b.Write(f.Data)

	return nil
}

func (f *StreamFrame) calculateStreamIDLength() uint8 {
	if f.StreamID < (1 << 8) {
		return 1
	} else if f.StreamID < (1 << 16) {
		return 2
	} else if f.StreamID < (1 << 24) {
		return 3
	}
	return 4
}

func (f *StreamFrame) getOffsetLength() protocol.ByteCount {
	if f.Offset == 0 {
		return 0
	}
	if f.Offset < (1 << 16) {
		return 2
	}
	if f.Offset < (1 << 24) {
		return 3
	}
	if f.Offset < (1 << 32) {
		return 4
	}
	if f.Offset < (1 << 40) {
		return 5
	}
	if f.Offset < (1 << 48) {
		return 6
	}
	if f.Offset < (1 << 56) {
		return 7
	}
	return 8
}

// MinLength returns the length of the header of a StreamFrame
// the total length of the StreamFrame is frame.MinLength() + frame.DataLen()
func (f *StreamFrame) MinLength(protocol.VersionNumber) (protocol.ByteCount, error) {
	length := protocol.ByteCount(1) + protocol.ByteCount(f.calculateStreamIDLength()) + f.getOffsetLength()
	if f.DataLenPresent {
		length += 2
	}

	return length, nil
}

// DataLen gives the length of data in bytes
func (f *StreamFrame) DataLen() protocol.ByteCount {
	return protocol.ByteCount(len(f.Data))
}
