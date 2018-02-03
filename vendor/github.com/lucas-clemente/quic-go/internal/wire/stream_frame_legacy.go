package wire

import (
	"bytes"
	"errors"
	"io"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/qerr"
)

var (
	errInvalidStreamIDLen = errors.New("StreamFrame: Invalid StreamID length")
	errInvalidOffsetLen   = errors.New("StreamFrame: Invalid offset length")
)

// parseLegacyStreamFrame reads a stream frame. The type byte must not have been read yet.
func parseLegacyStreamFrame(r *bytes.Reader, _ protocol.VersionNumber) (*StreamFrame, error) {
	frame := &StreamFrame{}

	typeByte, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	frame.FinBit = typeByte&0x40 > 0
	frame.DataLenPresent = typeByte&0x20 > 0
	offsetLen := typeByte & 0x1c >> 2
	if offsetLen != 0 {
		offsetLen++
	}
	streamIDLen := typeByte&0x3 + 1

	sid, err := utils.BigEndian.ReadUintN(r, streamIDLen)
	if err != nil {
		return nil, err
	}
	frame.StreamID = protocol.StreamID(sid)

	offset, err := utils.BigEndian.ReadUintN(r, offsetLen)
	if err != nil {
		return nil, err
	}
	frame.Offset = protocol.ByteCount(offset)

	var dataLen uint16
	if frame.DataLenPresent {
		dataLen, err = utils.BigEndian.ReadUint16(r)
		if err != nil {
			return nil, err
		}
	}

	// shortcut to prevent the unneccessary allocation of dataLen bytes
	// if the dataLen is larger than the remaining length of the packet
	// reading the packet contents would result in EOF when attempting to READ
	if int(dataLen) > r.Len() {
		return nil, io.EOF
	}

	if !frame.DataLenPresent {
		// The rest of the packet is data
		dataLen = uint16(r.Len())
	}
	if dataLen != 0 {
		frame.Data = make([]byte, dataLen)
		if _, err := io.ReadFull(r, frame.Data); err != nil {
			// this should never happen, since we already checked the dataLen earlier
			return nil, err
		}
	}

	// MaxByteCount is the highest value that can be encoded with the IETF QUIC variable integer encoding (2^62-1).
	// Note that this value is smaller than the maximum value that could be encoded in the gQUIC STREAM frame (2^64-1).
	if frame.Offset+frame.DataLen() > protocol.MaxByteCount {
		return nil, qerr.Error(qerr.InvalidStreamData, "data overflows maximum offset")
	}
	if !frame.FinBit && frame.DataLen() == 0 {
		return nil, qerr.EmptyStreamFrameNoFin
	}
	return frame, nil
}

// writeLegacy writes a stream frame.
func (f *StreamFrame) writeLegacy(b *bytes.Buffer, _ protocol.VersionNumber) error {
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
		utils.BigEndian.WriteUint16(b, uint16(f.StreamID))
	case 3:
		utils.BigEndian.WriteUint24(b, uint32(f.StreamID))
	case 4:
		utils.BigEndian.WriteUint32(b, uint32(f.StreamID))
	default:
		return errInvalidStreamIDLen
	}

	switch offsetLength {
	case 0:
	case 2:
		utils.BigEndian.WriteUint16(b, uint16(f.Offset))
	case 3:
		utils.BigEndian.WriteUint24(b, uint32(f.Offset))
	case 4:
		utils.BigEndian.WriteUint32(b, uint32(f.Offset))
	case 5:
		utils.BigEndian.WriteUint40(b, uint64(f.Offset))
	case 6:
		utils.BigEndian.WriteUint48(b, uint64(f.Offset))
	case 7:
		utils.BigEndian.WriteUint56(b, uint64(f.Offset))
	case 8:
		utils.BigEndian.WriteUint64(b, uint64(f.Offset))
	default:
		return errInvalidOffsetLen
	}

	if f.DataLenPresent {
		utils.BigEndian.WriteUint16(b, uint16(len(f.Data)))
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

func (f *StreamFrame) minLengthLegacy(_ protocol.VersionNumber) protocol.ByteCount {
	length := protocol.ByteCount(1) + protocol.ByteCount(f.calculateStreamIDLength()) + f.getOffsetLength()
	if f.DataLenPresent {
		length += 2
	}
	return length
}

// DataLen gives the length of data in bytes
func (f *StreamFrame) DataLen() protocol.ByteCount {
	return protocol.ByteCount(len(f.Data))
}
