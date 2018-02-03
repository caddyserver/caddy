package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

// A PingFrame is a ping frame
type PingFrame struct{}

// ParsePingFrame parses a Ping frame
func ParsePingFrame(r *bytes.Reader, version protocol.VersionNumber) (*PingFrame, error) {
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

// MinLength of a written frame
func (f *PingFrame) MinLength(version protocol.VersionNumber) protocol.ByteCount {
	return 1
}
