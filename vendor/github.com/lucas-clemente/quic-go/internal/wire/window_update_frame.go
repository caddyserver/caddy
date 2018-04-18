package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

type windowUpdateFrame struct {
	StreamID   protocol.StreamID
	ByteOffset protocol.ByteCount
}

// parseWindowUpdateFrame parses a WINDOW_UPDATE frame
// The frame returned is
// * a MAX_STREAM_DATA frame, if the WINDOW_UPDATE applies to a stream
// * a MAX_DATA frame, if the WINDOW_UPDATE applies to the connection
func parseWindowUpdateFrame(r *bytes.Reader, _ protocol.VersionNumber) (Frame, error) {
	if _, err := r.ReadByte(); err != nil { // read the TypeByte
		return nil, err
	}
	streamID, err := utils.BigEndian.ReadUint32(r)
	if err != nil {
		return nil, err
	}
	offset, err := utils.BigEndian.ReadUint64(r)
	if err != nil {
		return nil, err
	}
	if streamID == 0 {
		return &MaxDataFrame{ByteOffset: protocol.ByteCount(offset)}, nil
	}
	return &MaxStreamDataFrame{
		StreamID:   protocol.StreamID(streamID),
		ByteOffset: protocol.ByteCount(offset),
	}, nil
}

func (f *windowUpdateFrame) Write(b *bytes.Buffer, _ protocol.VersionNumber) error {
	b.WriteByte(0x4)
	utils.BigEndian.WriteUint32(b, uint32(f.StreamID))
	utils.BigEndian.WriteUint64(b, uint64(f.ByteOffset))
	return nil
}
