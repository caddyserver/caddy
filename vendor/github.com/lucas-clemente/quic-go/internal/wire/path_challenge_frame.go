package wire

import (
	"bytes"
	"io"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

// A PathChallengeFrame is a PATH_CHALLENGE frame
type PathChallengeFrame struct {
	Data [8]byte
}

func parsePathChallengeFrame(r *bytes.Reader, version protocol.VersionNumber) (*PathChallengeFrame, error) {
	if _, err := r.ReadByte(); err != nil {
		return nil, err
	}
	frame := &PathChallengeFrame{}
	if _, err := io.ReadFull(r, frame.Data[:]); err != nil {
		if err == io.ErrUnexpectedEOF {
			return nil, io.EOF
		}
		return nil, err
	}
	return frame, nil
}

func (f *PathChallengeFrame) Write(b *bytes.Buffer, _ protocol.VersionNumber) error {
	typeByte := uint8(0x0e)
	b.WriteByte(typeByte)
	b.Write(f.Data[:])
	return nil
}

// Length of a written frame
func (f *PathChallengeFrame) Length(_ protocol.VersionNumber) protocol.ByteCount {
	return 1 + 8
}
