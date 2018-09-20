package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

// A MaxStreamDataFrame carries flow control information for a stream
type MaxStreamDataFrame struct {
	StreamID   protocol.StreamID
	ByteOffset protocol.ByteCount
}

// parseMaxStreamDataFrame parses a MAX_STREAM_DATA frame
func parseMaxStreamDataFrame(r *bytes.Reader, version protocol.VersionNumber) (*MaxStreamDataFrame, error) {
	frame := &MaxStreamDataFrame{}

	// read the TypeByte
	if _, err := r.ReadByte(); err != nil {
		return nil, err
	}

	sid, err := utils.ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	frame.StreamID = protocol.StreamID(sid)

	byteOffset, err := utils.ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	frame.ByteOffset = protocol.ByteCount(byteOffset)
	return frame, nil
}

// Write writes a MAX_STREAM_DATA frame
func (f *MaxStreamDataFrame) Write(b *bytes.Buffer, version protocol.VersionNumber) error {
	if !version.UsesIETFFrameFormat() {
		return (&windowUpdateFrame{
			StreamID:   f.StreamID,
			ByteOffset: f.ByteOffset,
		}).Write(b, version)
	}
	b.WriteByte(0x5)
	utils.WriteVarInt(b, uint64(f.StreamID))
	utils.WriteVarInt(b, uint64(f.ByteOffset))
	return nil
}

// Length of a written frame
func (f *MaxStreamDataFrame) Length(version protocol.VersionNumber) protocol.ByteCount {
	// writing this frame would result in a gQUIC WINDOW_UPDATE being written, which has a different length
	if !version.UsesIETFFrameFormat() {
		return 1 + 4 + 8
	}
	return 1 + utils.VarIntLen(uint64(f.StreamID)) + utils.VarIntLen(uint64(f.ByteOffset))
}
