package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

// A PingFrame is a ping frame
type PingFrame struct{}

// parsePingFrame parses a Ping frame
func parsePingFrame(r *bytes.Reader, version protocol.VersionNumber) (*PingFrame, error) {
	frame := &PingFrame{}

	_, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	return frame, nil
}

func (f *PingFrame) Write(b *bytes.Buffer, version protocol.VersionNumber) error {
	typeByte := uint8(0x07)
	b.WriteByte(typeByte)
	return nil
}

// Length of a written frame
func (f *PingFrame) Length(version protocol.VersionNumber) protocol.ByteCount {
	return 1
}
