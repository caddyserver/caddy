package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

// A MaxDataFrame carries flow control information for the connection
type MaxDataFrame struct {
	ByteOffset protocol.ByteCount
}

// parseMaxDataFrame parses a MAX_DATA frame
func parseMaxDataFrame(r *bytes.Reader, version protocol.VersionNumber) (*MaxDataFrame, error) {
	// read the TypeByte
	if _, err := r.ReadByte(); err != nil {
		return nil, err
	}

	frame := &MaxDataFrame{}
	byteOffset, err := utils.ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	frame.ByteOffset = protocol.ByteCount(byteOffset)
	return frame, nil
}

//Write writes a MAX_STREAM_DATA frame
func (f *MaxDataFrame) Write(b *bytes.Buffer, version protocol.VersionNumber) error {
	if !version.UsesIETFFrameFormat() {
		// write a gQUIC WINDOW_UPDATE frame (with stream ID 0, which means connection-level there)
		return (&windowUpdateFrame{
			StreamID:   0,
			ByteOffset: f.ByteOffset,
		}).Write(b, version)
	}
	b.WriteByte(0x4)
	utils.WriteVarInt(b, uint64(f.ByteOffset))
	return nil
}

// Length of a written frame
func (f *MaxDataFrame) Length(version protocol.VersionNumber) protocol.ByteCount {
	if !version.UsesIETFFrameFormat() { // writing this frame would result in a gQUIC WINDOW_UPDATE being written, which is longer
		return 1 + 4 + 8
	}
	return 1 + utils.VarIntLen(uint64(f.ByteOffset))
}
