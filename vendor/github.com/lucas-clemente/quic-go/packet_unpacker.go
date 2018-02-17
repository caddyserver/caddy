package quic

import (
	"bytes"
	"fmt"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"github.com/lucas-clemente/quic-go/qerr"
)

type unpackedPacket struct {
	encryptionLevel protocol.EncryptionLevel
	frames          []wire.Frame
}

type quicAEAD interface {
	Open(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, protocol.EncryptionLevel, error)
}

type packetUnpacker struct {
	version protocol.VersionNumber
	aead    quicAEAD
}

func (u *packetUnpacker) Unpack(headerBinary []byte, hdr *wire.Header, data []byte) (*unpackedPacket, error) {
	buf := getPacketBuffer()
	defer putPacketBuffer(buf)
	decrypted, encryptionLevel, err := u.aead.Open(buf, data, hdr.PacketNumber, headerBinary)
	if err != nil {
		// Wrap err in quicError so that public reset is sent by session
		return nil, qerr.Error(qerr.DecryptionFailure, err.Error())
	}
	r := bytes.NewReader(decrypted)

	if r.Len() == 0 {
		return nil, qerr.MissingPayload
	}

	fs := make([]wire.Frame, 0, 2)

	// Read all frames in the packet
	for r.Len() > 0 {
		typeByte, _ := r.ReadByte()
		if typeByte == 0x0 { // PADDING frame
			continue
		}
		r.UnreadByte()

		frame, err := u.parseFrame(r, typeByte, hdr)
		if err != nil {
			return nil, err
		}
		if sf, ok := frame.(*wire.StreamFrame); ok {
			if sf.StreamID != u.version.CryptoStreamID() && encryptionLevel <= protocol.EncryptionUnencrypted {
				return nil, qerr.Error(qerr.UnencryptedStreamData, fmt.Sprintf("received unencrypted stream data on stream %d", sf.StreamID))
			}
		}
		if frame != nil {
			fs = append(fs, frame)
		}
	}

	return &unpackedPacket{
		encryptionLevel: encryptionLevel,
		frames:          fs,
	}, nil
}

func (u *packetUnpacker) parseFrame(r *bytes.Reader, typeByte byte, hdr *wire.Header) (wire.Frame, error) {
	if u.version.UsesIETFFrameFormat() {
		return u.parseIETFFrame(r, typeByte, hdr)
	}
	return u.parseGQUICFrame(r, typeByte, hdr)
}

func (u *packetUnpacker) parseIETFFrame(r *bytes.Reader, typeByte byte, hdr *wire.Header) (wire.Frame, error) {
	var frame wire.Frame
	var err error
	if typeByte&0xf8 == 0x10 {
		frame, err = wire.ParseStreamFrame(r, u.version)
		if err != nil {
			err = qerr.Error(qerr.InvalidStreamData, err.Error())
		}
		return frame, err
	}
	// TODO: implement all IETF QUIC frame types
	switch typeByte {
	case 0x1:
		frame, err = wire.ParseRstStreamFrame(r, u.version)
		if err != nil {
			err = qerr.Error(qerr.InvalidRstStreamData, err.Error())
		}
	case 0x2:
		frame, err = wire.ParseConnectionCloseFrame(r, u.version)
		if err != nil {
			err = qerr.Error(qerr.InvalidConnectionCloseData, err.Error())
		}
	case 0x4:
		frame, err = wire.ParseMaxDataFrame(r, u.version)
		if err != nil {
			err = qerr.Error(qerr.InvalidWindowUpdateData, err.Error())
		}
	case 0x5:
		frame, err = wire.ParseMaxStreamDataFrame(r, u.version)
		if err != nil {
			err = qerr.Error(qerr.InvalidWindowUpdateData, err.Error())
		}
	case 0x6:
		frame, err = wire.ParseMaxStreamIDFrame(r, u.version)
		if err != nil {
			err = qerr.Error(qerr.InvalidFrameData, err.Error())
		}
	case 0x7:
		frame, err = wire.ParsePingFrame(r, u.version)
	case 0x8:
		frame, err = wire.ParseBlockedFrame(r, u.version)
		if err != nil {
			err = qerr.Error(qerr.InvalidBlockedData, err.Error())
		}
	case 0x9:
		frame, err = wire.ParseStreamBlockedFrame(r, u.version)
		if err != nil {
			err = qerr.Error(qerr.InvalidBlockedData, err.Error())
		}
	case 0xa:
		frame, err = wire.ParseStreamIDBlockedFrame(r, u.version)
		if err != nil {
			err = qerr.Error(qerr.InvalidFrameData, err.Error())
		}
	case 0xc:
		frame, err = wire.ParseStopSendingFrame(r, u.version)
		if err != nil {
			err = qerr.Error(qerr.InvalidFrameData, err.Error())
		}
	case 0xe:
		frame, err = wire.ParseAckFrame(r, u.version)
		if err != nil {
			err = qerr.Error(qerr.InvalidAckData, err.Error())
		}
	default:
		err = qerr.Error(qerr.InvalidFrameData, fmt.Sprintf("unknown type byte 0x%x", typeByte))
	}
	return frame, err
}

func (u *packetUnpacker) parseGQUICFrame(r *bytes.Reader, typeByte byte, hdr *wire.Header) (wire.Frame, error) {
	var frame wire.Frame
	var err error
	if typeByte&0x80 == 0x80 {
		frame, err = wire.ParseStreamFrame(r, u.version)
		if err != nil {
			err = qerr.Error(qerr.InvalidStreamData, err.Error())
		}
		return frame, err
	} else if typeByte&0xc0 == 0x40 {
		frame, err = wire.ParseAckFrame(r, u.version)
		if err != nil {
			err = qerr.Error(qerr.InvalidAckData, err.Error())
		}
		return frame, err
	}
	switch typeByte {
	case 0x1:
		frame, err = wire.ParseRstStreamFrame(r, u.version)
		if err != nil {
			err = qerr.Error(qerr.InvalidRstStreamData, err.Error())
		}
	case 0x2:
		frame, err = wire.ParseConnectionCloseFrame(r, u.version)
		if err != nil {
			err = qerr.Error(qerr.InvalidConnectionCloseData, err.Error())
		}
	case 0x3:
		frame, err = wire.ParseGoawayFrame(r, u.version)
		if err != nil {
			err = qerr.Error(qerr.InvalidGoawayData, err.Error())
		}
	case 0x4:
		frame, err = wire.ParseWindowUpdateFrame(r, u.version)
		if err != nil {
			err = qerr.Error(qerr.InvalidWindowUpdateData, err.Error())
		}
	case 0x5:
		frame, err = wire.ParseBlockedFrameLegacy(r, u.version)
		if err != nil {
			err = qerr.Error(qerr.InvalidBlockedData, err.Error())
		}
	case 0x6:
		frame, err = wire.ParseStopWaitingFrame(r, hdr.PacketNumber, hdr.PacketNumberLen, u.version)
		if err != nil {
			err = qerr.Error(qerr.InvalidStopWaitingData, err.Error())
		}
	case 0x7:
		frame, err = wire.ParsePingFrame(r, u.version)
	default:
		err = qerr.Error(qerr.InvalidFrameData, fmt.Sprintf("unknown type byte 0x%x", typeByte))
	}
	return frame, err
}
