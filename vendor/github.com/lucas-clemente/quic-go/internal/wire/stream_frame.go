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

// parseStreamFrame reads a STREAM frame
func parseStreamFrame(r *bytes.Reader, version protocol.VersionNumber) (*StreamFrame, error) {
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
		// shortcut to prevent the unnecessary allocation of dataLen bytes
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

// Length returns the total length of the STREAM frame
func (f *StreamFrame) Length(version protocol.VersionNumber) protocol.ByteCount {
	if !version.UsesIETFFrameFormat() {
		return f.lengthLegacy(version)
	}
	length := 1 + utils.VarIntLen(uint64(f.StreamID))
	if f.Offset != 0 {
		length += utils.VarIntLen(uint64(f.Offset))
	}
	if f.DataLenPresent {
		length += utils.VarIntLen(uint64(f.DataLen()))
	}
	return length + f.DataLen()
}

// MaxDataLen returns the maximum data length
// If 0 is returned, writing will fail (a STREAM frame must contain at least 1 byte of data).
func (f *StreamFrame) MaxDataLen(maxSize protocol.ByteCount, version protocol.VersionNumber) protocol.ByteCount {
	if !version.UsesIETFFrameFormat() {
		return f.maxDataLenLegacy(maxSize, version)
	}

	headerLen := 1 + utils.VarIntLen(uint64(f.StreamID))
	if f.Offset != 0 {
		headerLen += utils.VarIntLen(uint64(f.Offset))
	}
	if f.DataLenPresent {
		// pretend that the data size will be 1 bytes
		// if it turns out that varint encoding the length will consume 2 bytes, we need to adjust the data length afterwards
		headerLen++
	}
	if headerLen > maxSize {
		return 0
	}
	maxDataLen := maxSize - headerLen
	if f.DataLenPresent && utils.VarIntLen(uint64(maxDataLen)) != 1 {
		maxDataLen--
	}
	return maxDataLen
}

// MaybeSplitOffFrame splits a frame such that it is not bigger than n bytes.
// If n >= len(frame), nil is returned and nothing is modified.
func (f *StreamFrame) MaybeSplitOffFrame(maxSize protocol.ByteCount, version protocol.VersionNumber) (*StreamFrame, error) {
	if maxSize >= f.Length(version) {
		return nil, nil
	}

	n := f.MaxDataLen(maxSize, version)
	if n == 0 {
		return nil, errors.New("too small")
	}
	newFrame := &StreamFrame{
		FinBit:         false,
		StreamID:       f.StreamID,
		Offset:         f.Offset,
		Data:           f.Data[:n],
		DataLenPresent: f.DataLenPresent,
	}

	f.Data = f.Data[n:]
	f.Offset += n

	return newFrame, nil
}
