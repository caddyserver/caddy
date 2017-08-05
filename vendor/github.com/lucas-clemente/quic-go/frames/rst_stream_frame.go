package frames

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/protocol"
)

// A RstStreamFrame in QUIC
type RstStreamFrame struct {
	StreamID   protocol.StreamID
	ErrorCode  uint32
	ByteOffset protocol.ByteCount
}

//Write writes a RST_STREAM frame
func (f *RstStreamFrame) Write(b *bytes.Buffer, version protocol.VersionNumber) error {
	b.WriteByte(0x01)
	utils.WriteUint32(b, uint32(f.StreamID))
	utils.WriteUint64(b, uint64(f.ByteOffset))
	utils.WriteUint32(b, f.ErrorCode)
	return nil
}

// MinLength of a written frame
func (f *RstStreamFrame) MinLength(version protocol.VersionNumber) (protocol.ByteCount, error) {
	return 1 + 4 + 8 + 4, nil
}

// ParseRstStreamFrame parses a RST_STREAM frame
func ParseRstStreamFrame(r *bytes.Reader) (*RstStreamFrame, error) {
	frame := &RstStreamFrame{}

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

	byteOffset, err := utils.ReadUint64(r)
	if err != nil {
		return nil, err
	}
	frame.ByteOffset = protocol.ByteCount(byteOffset)

	frame.ErrorCode, err = utils.ReadUint32(r)
	if err != nil {
		return nil, err
	}

	return frame, nil
}
