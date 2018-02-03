package wire

import (
	"bytes"
	"errors"
	"io"
	"math"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/qerr"
)

// A ConnectionCloseFrame in QUIC
type ConnectionCloseFrame struct {
	ErrorCode    qerr.ErrorCode
	ReasonPhrase string
}

// ParseConnectionCloseFrame reads a CONNECTION_CLOSE frame
func ParseConnectionCloseFrame(r *bytes.Reader, version protocol.VersionNumber) (*ConnectionCloseFrame, error) {
	if _, err := r.ReadByte(); err != nil { // read the TypeByte
		return nil, err
	}

	var errorCode qerr.ErrorCode
	var reasonPhraseLen uint64
	if version.UsesIETFFrameFormat() {
		ec, err := utils.BigEndian.ReadUint16(r)
		if err != nil {
			return nil, err
		}
		errorCode = qerr.ErrorCode(ec)
		reasonPhraseLen, err = utils.ReadVarInt(r)
		if err != nil {
			return nil, err
		}
	} else {
		ec, err := utils.BigEndian.ReadUint32(r)
		if err != nil {
			return nil, err
		}
		errorCode = qerr.ErrorCode(ec)
		length, err := utils.BigEndian.ReadUint16(r)
		if err != nil {
			return nil, err
		}
		reasonPhraseLen = uint64(length)
	}

	// shortcut to prevent the unneccessary allocation of dataLen bytes
	// if the dataLen is larger than the remaining length of the packet
	// reading the whole reason phrase would result in EOF when attempting to READ
	if int(reasonPhraseLen) > r.Len() {
		return nil, io.EOF
	}

	reasonPhrase := make([]byte, reasonPhraseLen)
	if _, err := io.ReadFull(r, reasonPhrase); err != nil {
		// this should never happen, since we already checked the reasonPhraseLen earlier
		return nil, err
	}

	return &ConnectionCloseFrame{
		ErrorCode:    qerr.ErrorCode(errorCode),
		ReasonPhrase: string(reasonPhrase),
	}, nil
}

// MinLength of a written frame
func (f *ConnectionCloseFrame) MinLength(version protocol.VersionNumber) protocol.ByteCount {
	if version.UsesIETFFrameFormat() {
		return 1 + 2 + utils.VarIntLen(uint64(len(f.ReasonPhrase))) + protocol.ByteCount(len(f.ReasonPhrase))
	}
	return 1 + 4 + 2 + protocol.ByteCount(len(f.ReasonPhrase))
}

// Write writes an CONNECTION_CLOSE frame.
func (f *ConnectionCloseFrame) Write(b *bytes.Buffer, version protocol.VersionNumber) error {
	b.WriteByte(0x02)

	if len(f.ReasonPhrase) > math.MaxUint16 {
		return errors.New("ConnectionFrame: ReasonPhrase too long")
	}

	if version.UsesIETFFrameFormat() {
		utils.BigEndian.WriteUint16(b, uint16(f.ErrorCode))
		utils.WriteVarInt(b, uint64(len(f.ReasonPhrase)))
	} else {
		utils.BigEndian.WriteUint32(b, uint32(f.ErrorCode))
		utils.BigEndian.WriteUint16(b, uint16(len(f.ReasonPhrase)))
	}
	b.WriteString(f.ReasonPhrase)

	return nil
}
