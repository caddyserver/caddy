package frames

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/protocol"
)

// A BlockedFrame in QUIC
type BlockedFrame struct {
	StreamID protocol.StreamID
}

//Write writes a BlockedFrame frame
func (f *BlockedFrame) Write(b *bytes.Buffer, version protocol.VersionNumber) error {
	b.WriteByte(0x05)
	utils.WriteUint32(b, uint32(f.StreamID))
	return nil
}

// MinLength of a written frame
func (f *BlockedFrame) MinLength(version protocol.VersionNumber) (protocol.ByteCount, error) {
	return 1 + 4, nil
}

// ParseBlockedFrame parses a BLOCKED frame
func ParseBlockedFrame(r *bytes.Reader) (*BlockedFrame, error) {
	frame := &BlockedFrame{}

	// read the TypeByte
	_, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	sid, err := utils.ReadUint32(r)
	if err != nil {
		return nil, err
	}
	frame.StreamID = protocol.StreamID(sid)

	return frame, nil
}
