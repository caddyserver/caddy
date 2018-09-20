package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

// A BlockedFrame is a BLOCKED frame
type BlockedFrame struct {
	Offset protocol.ByteCount
}

// parseBlockedFrame parses a BLOCKED frame
func parseBlockedFrame(r *bytes.Reader, _ protocol.VersionNumber) (*BlockedFrame, error) {
	if _, err := r.ReadByte(); err != nil {
		return nil, err
	}
	offset, err := utils.ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	return &BlockedFrame{
		Offset: protocol.ByteCount(offset),
	}, nil
}

func (f *BlockedFrame) Write(b *bytes.Buffer, version protocol.VersionNumber) error {
	if !version.UsesIETFFrameFormat() {
		return (&blockedFrameLegacy{}).Write(b, version)
	}
	typeByte := uint8(0x08)
	b.WriteByte(typeByte)
	utils.WriteVarInt(b, uint64(f.Offset))
	return nil
}

// Length of a written frame
func (f *BlockedFrame) Length(version protocol.VersionNumber) protocol.ByteCount {
	if !version.UsesIETFFrameFormat() {
		return 1 + 4
	}
	return 1 + utils.VarIntLen(uint64(f.Offset))
}
