package frames

import (
	"bytes"
	"errors"
	"io"
	"math"

	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
)

// A ConnectionCloseFrame in QUIC
type ConnectionCloseFrame struct {
	ErrorCode    qerr.ErrorCode
	ReasonPhrase string
}

// ParseConnectionCloseFrame reads a CONNECTION_CLOSE frame
func ParseConnectionCloseFrame(r *bytes.Reader) (*ConnectionCloseFrame, error) {
	frame := &ConnectionCloseFrame{}

	// read the TypeByte
	_, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	errorCode, err := utils.ReadUint32(r)
	if err != nil {
		return nil, err
	}
	frame.ErrorCode = qerr.ErrorCode(errorCode)

	reasonPhraseLen, err := utils.ReadUint16(r)
	if err != nil {
		return nil, err
	}

	if reasonPhraseLen > uint16(protocol.MaxPacketSize) {
		return nil, qerr.Error(qerr.InvalidConnectionCloseData, "reason phrase too long")
	}

	reasonPhrase := make([]byte, reasonPhraseLen)
	if _, err := io.ReadFull(r, reasonPhrase); err != nil {
		return nil, err
	}
	frame.ReasonPhrase = string(reasonPhrase)

	return frame, nil
}

// MinLength of a written frame
func (f *ConnectionCloseFrame) MinLength(version protocol.VersionNumber) (protocol.ByteCount, error) {
	return 1 + 4 + 2 + protocol.ByteCount(len(f.ReasonPhrase)), nil
}

// Write writes an CONNECTION_CLOSE frame.
func (f *ConnectionCloseFrame) Write(b *bytes.Buffer, version protocol.VersionNumber) error {
	b.WriteByte(0x02)
	utils.WriteUint32(b, uint32(f.ErrorCode))

	if len(f.ReasonPhrase) > math.MaxUint16 {
		return errors.New("ConnectionFrame: ReasonPhrase too long")
	}

	reasonPhraseLen := uint16(len(f.ReasonPhrase))
	utils.WriteUint16(b, reasonPhraseLen)
	b.WriteString(f.ReasonPhrase)

	return nil
}
