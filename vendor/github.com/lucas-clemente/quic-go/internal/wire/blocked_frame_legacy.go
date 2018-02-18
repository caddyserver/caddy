package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

type blockedFrameLegacy struct {
	StreamID protocol.StreamID
}

// ParseBlockedFrameLegacy parses a BLOCKED frame (in gQUIC format)
// The frame returned is
// * a STREAM_BLOCKED frame, if the BLOCKED applies to a stream
// * a BLOCKED frame, if the BLOCKED applies to the connection
func ParseBlockedFrameLegacy(r *bytes.Reader, _ protocol.VersionNumber) (Frame, error) {
	if _, err := r.ReadByte(); err != nil { // read the TypeByte
		return nil, err
	}
	streamID, err := utils.BigEndian.ReadUint32(r)
	if err != nil {
		return nil, err
	}
	if streamID == 0 {
		return &BlockedFrame{}, nil
	}
	return &StreamBlockedFrame{StreamID: protocol.StreamID(streamID)}, nil
}

//Write writes a BLOCKED frame
func (f *blockedFrameLegacy) Write(b *bytes.Buffer, _ protocol.VersionNumber) error {
	b.WriteByte(0x05)
	utils.BigEndian.WriteUint32(b, uint32(f.StreamID))
	return nil
}
