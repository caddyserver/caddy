package wire

import (
	"bytes"
	"io"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/qerr"
)

// A GoawayFrame is a GOAWAY frame
type GoawayFrame struct {
	ErrorCode      qerr.ErrorCode
	LastGoodStream protocol.StreamID
	ReasonPhrase   string
}

// parseGoawayFrame parses a GOAWAY frame
func parseGoawayFrame(r *bytes.Reader, _ protocol.VersionNumber) (*GoawayFrame, error) {
	frame := &GoawayFrame{}

	if _, err := r.ReadByte(); err != nil {
		return nil, err
	}

	errorCode, err := utils.BigEndian.ReadUint32(r)
	if err != nil {
		return nil, err
	}
	frame.ErrorCode = qerr.ErrorCode(errorCode)

	lastGoodStream, err := utils.BigEndian.ReadUint32(r)
	if err != nil {
		return nil, err
	}
	frame.LastGoodStream = protocol.StreamID(lastGoodStream)

	reasonPhraseLen, err := utils.BigEndian.ReadUint16(r)
	if err != nil {
		return nil, err
	}

	if reasonPhraseLen > uint16(protocol.MaxReceivePacketSize) {
		return nil, qerr.Error(qerr.InvalidGoawayData, "reason phrase too long")
	}

	reasonPhrase := make([]byte, reasonPhraseLen)
	if _, err := io.ReadFull(r, reasonPhrase); err != nil {
		return nil, err
	}
	frame.ReasonPhrase = string(reasonPhrase)
	return frame, nil
}

func (f *GoawayFrame) Write(b *bytes.Buffer, _ protocol.VersionNumber) error {
	b.WriteByte(0x03)
	utils.BigEndian.WriteUint32(b, uint32(f.ErrorCode))
	utils.BigEndian.WriteUint32(b, uint32(f.LastGoodStream))
	utils.BigEndian.WriteUint16(b, uint16(len(f.ReasonPhrase)))
	b.WriteString(f.ReasonPhrase)
	return nil
}

// Length of a written frame
func (f *GoawayFrame) Length(version protocol.VersionNumber) protocol.ByteCount {
	return protocol.ByteCount(1 + 4 + 4 + 2 + len(f.ReasonPhrase))
}
