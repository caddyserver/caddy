package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

// A RstStreamFrame is a RST_STREAM frame in QUIC
type RstStreamFrame struct {
	StreamID protocol.StreamID
	// The error code is a uint32 in gQUIC, but a uint16 in IETF QUIC.
	// protocol.ApplicaitonErrorCode is a uint16, so larger values in gQUIC frames will be truncated.
	ErrorCode  protocol.ApplicationErrorCode
	ByteOffset protocol.ByteCount
}

// parseRstStreamFrame parses a RST_STREAM frame
func parseRstStreamFrame(r *bytes.Reader, version protocol.VersionNumber) (*RstStreamFrame, error) {
	if _, err := r.ReadByte(); err != nil { // read the TypeByte
		return nil, err
	}

	var streamID protocol.StreamID
	var errorCode uint16
	var byteOffset protocol.ByteCount
	if version.UsesIETFFrameFormat() {
		sid, err := utils.ReadVarInt(r)
		if err != nil {
			return nil, err
		}
		streamID = protocol.StreamID(sid)
		errorCode, err = utils.BigEndian.ReadUint16(r)
		if err != nil {
			return nil, err
		}
		bo, err := utils.ReadVarInt(r)
		if err != nil {
			return nil, err
		}
		byteOffset = protocol.ByteCount(bo)
	} else {
		sid, err := utils.BigEndian.ReadUint32(r)
		if err != nil {
			return nil, err
		}
		streamID = protocol.StreamID(sid)
		bo, err := utils.BigEndian.ReadUint64(r)
		if err != nil {
			return nil, err
		}
		byteOffset = protocol.ByteCount(bo)
		ec, err := utils.BigEndian.ReadUint32(r)
		if err != nil {
			return nil, err
		}
		errorCode = uint16(ec)
	}

	return &RstStreamFrame{
		StreamID:   streamID,
		ErrorCode:  protocol.ApplicationErrorCode(errorCode),
		ByteOffset: byteOffset,
	}, nil
}

//Write writes a RST_STREAM frame
func (f *RstStreamFrame) Write(b *bytes.Buffer, version protocol.VersionNumber) error {
	b.WriteByte(0x01)
	if version.UsesIETFFrameFormat() {
		utils.WriteVarInt(b, uint64(f.StreamID))
		utils.BigEndian.WriteUint16(b, uint16(f.ErrorCode))
		utils.WriteVarInt(b, uint64(f.ByteOffset))
	} else {
		utils.BigEndian.WriteUint32(b, uint32(f.StreamID))
		utils.BigEndian.WriteUint64(b, uint64(f.ByteOffset))
		utils.BigEndian.WriteUint32(b, uint32(f.ErrorCode))
	}
	return nil
}

// Length of a written frame
func (f *RstStreamFrame) Length(version protocol.VersionNumber) protocol.ByteCount {
	if version.UsesIETFFrameFormat() {
		return 1 + utils.VarIntLen(uint64(f.StreamID)) + 2 + utils.VarIntLen(uint64(f.ByteOffset))
	}
	return 1 + 4 + 8 + 4
}
