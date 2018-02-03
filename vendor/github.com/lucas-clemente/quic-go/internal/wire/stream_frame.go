package wire

import (
	"bytes"
	"errors"
	"io"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
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

// ParseStreamFrame reads a STREAM frame
func ParseStreamFrame(r *bytes.Reader, version protocol.VersionNumber) (*StreamFrame, error) {
	if !version.UsesIETFFrameFormat() {
		return parseLegacyStreamFrame(r, version)
	}

	frame := &StreamFrame{}

	typeByte, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	frame.FinBit = typeByte&0x1 > 0
	frame.DataLenPresent = typeByte&0x2 > 0
	hasOffset := typeByte&0x4 > 0

	streamID, err := utils.ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	frame.StreamID = protocol.StreamID(streamID)
	if hasOffset {
		offset, err := utils.ReadVarInt(r)
		if err != nil {
			return nil, err
		}
		frame.Offset = protocol.ByteCount(offset)
	}

	var dataLen uint64
	if frame.DataLenPresent {
		var err error
		dataLen, err = utils.ReadVarInt(r)
		if err != nil {
			return nil, err
		}
		// shortcut to prevent the unneccessary allocation of dataLen bytes
		// if the dataLen is larger than the remaining length of the packet
		// reading the packet contents would result in EOF when attempting to READ
		if dataLen > uint64(r.Len()) {
			return nil, io.EOF
		}
	} else {
		// The rest of the packet is data
		dataLen = uint64(r.Len())
	}
	if dataLen != 0 {
		frame.Data = make([]byte, dataLen)
		if _, err := io.ReadFull(r, frame.Data); err != nil {
			// this should never happen, since we already checked the dataLen earlier
			return nil, err
		}
	}
	if frame.Offset+frame.DataLen() > protocol.MaxByteCount {
		return nil, qerr.Error(qerr.InvalidStreamData, "data overflows maximum offset")
	}
	if !frame.FinBit && frame.DataLen() == 0 {
		return nil, qerr.EmptyStreamFrameNoFin
	}
	return frame, nil
}

// Write writes a STREAM frame
func (f *StreamFrame) Write(b *bytes.Buffer, version protocol.VersionNumber) error {
	if !version.UsesIETFFrameFormat() {
		return f.writeLegacy(b, version)
	}

	if len(f.Data) == 0 && !f.FinBit {
		return errors.New("StreamFrame: attempting to write empty frame without FIN")
	}

	typeByte := byte(0x10)
	if f.FinBit {
		typeByte ^= 0x1
	}
	hasOffset := f.Offset != 0
	if f.DataLenPresent {
		typeByte ^= 0x2
	}
	if hasOffset {
		typeByte ^= 0x4
	}
	b.WriteByte(typeByte)
	utils.WriteVarInt(b, uint64(f.StreamID))
	if hasOffset {
		utils.WriteVarInt(b, uint64(f.Offset))
	}
	if f.DataLenPresent {
		utils.WriteVarInt(b, uint64(f.DataLen()))
	}
	b.Write(f.Data)
	return nil
}

// MinLength returns the length of the header of a StreamFrame
// the total length of the frame is frame.MinLength() + frame.DataLen()
func (f *StreamFrame) MinLength(version protocol.VersionNumber) protocol.ByteCount {
	if !version.UsesIETFFrameFormat() {
		return f.minLengthLegacy(version)
	}
	length := 1 + utils.VarIntLen(uint64(f.StreamID))
	if f.Offset != 0 {
		length += utils.VarIntLen(uint64(f.Offset))
	}
	if f.DataLenPresent {
		length += utils.VarIntLen(uint64(f.DataLen()))
	}
	return length
}
