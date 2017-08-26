package frames

import (
	"bytes"
	"io"

	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
)

// A GoawayFrame is a GOAWAY frame
type GoawayFrame struct {
	ErrorCode      qerr.ErrorCode
	LastGoodStream protocol.StreamID
	ReasonPhrase   string
}

// ParseGoawayFrame parses a GOAWAY frame
func ParseGoawayFrame(r *bytes.Reader) (*GoawayFrame, error) {
	frame := &GoawayFrame{}

	_, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	errorCode, err := utils.ReadUint32(r)
	if err != nil {
		return nil, err
	}
	frame.ErrorCode = qerr.ErrorCode(errorCode)

	lastGoodStream, err := utils.ReadUint32(r)
	if err != nil {
		return nil, err
	}
	frame.LastGoodStream = protocol.StreamID(lastGoodStream)

	reasonPhraseLen, err := utils.ReadUint16(r)
	if err != nil {
		return nil, err
	}

	if reasonPhraseLen > uint16(protocol.MaxPacketSize) {
		return nil, qerr.Error(qerr.InvalidGoawayData, "reason phrase too long")
	}

	reasonPhrase := make([]byte, reasonPhraseLen)
	if _, err := io.ReadFull(r, reasonPhrase); err != nil {
		return nil, err
	}
	frame.ReasonPhrase = string(reasonPhrase)

	return frame, nil
}

func (f *GoawayFrame) Write(b *bytes.Buffer, version protocol.VersionNumber) error {
	typeByte := uint8(0x03)
	b.WriteByte(typeByte)

	utils.WriteUint32(b, uint32(f.ErrorCode))
	utils.WriteUint32(b, uint32(f.LastGoodStream))
	utils.WriteUint16(b, uint16(len(f.ReasonPhrase)))
	b.WriteString(f.ReasonPhrase)

	return nil
}

// MinLength of a written frame
func (f *GoawayFrame) MinLength(version protocol.VersionNumber) (protocol.ByteCount, error) {
	return protocol.ByteCount(1 + 4 + 4 + 2 + len(f.ReasonPhrase)), nil
}
