package quic

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
)

type unpackedPacket struct {
	encryptionLevel protocol.EncryptionLevel
	frames          []frames.Frame
}

type quicAEAD interface {
	Open(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, protocol.EncryptionLevel, error)
}

type packetUnpacker struct {
	version protocol.VersionNumber
	aead    quicAEAD
}

func (u *packetUnpacker) Unpack(publicHeaderBinary []byte, hdr *PublicHeader, data []byte) (*unpackedPacket, error) {
	buf := getPacketBuffer()
	defer putPacketBuffer(buf)
	decrypted, encryptionLevel, err := u.aead.Open(buf, data, hdr.PacketNumber, publicHeaderBinary)
	if err != nil {
		// Wrap err in quicError so that public reset is sent by session
		return nil, qerr.Error(qerr.DecryptionFailure, err.Error())
	}
	r := bytes.NewReader(decrypted)

	if r.Len() == 0 {
		return nil, qerr.MissingPayload
	}

	fs := make([]frames.Frame, 0, 2)

	// Read all frames in the packet
	for r.Len() > 0 {
		typeByte, _ := r.ReadByte()
		if typeByte == 0x0 { // PADDING frame
			continue
		}
		r.UnreadByte()

		var frame frames.Frame
		if typeByte&0x80 == 0x80 {
			frame, err = frames.ParseStreamFrame(r)
			if err != nil {
				err = qerr.Error(qerr.InvalidStreamData, err.Error())
			} else {
				streamID := frame.(*frames.StreamFrame).StreamID
				if streamID != 1 && encryptionLevel <= protocol.EncryptionUnencrypted {
					err = qerr.Error(qerr.UnencryptedStreamData, fmt.Sprintf("received unencrypted stream data on stream %d", streamID))
				}
			}
		} else if typeByte&0xc0 == 0x40 {
			frame, err = frames.ParseAckFrame(r, u.version)
			if err != nil {
				err = qerr.Error(qerr.InvalidAckData, err.Error())
			}
		} else if typeByte&0xe0 == 0x20 {
			err = errors.New("unimplemented: CONGESTION_FEEDBACK")
		} else {
			switch typeByte {
			case 0x01:
				frame, err = frames.ParseRstStreamFrame(r)
				if err != nil {
					err = qerr.Error(qerr.InvalidRstStreamData, err.Error())
				}
			case 0x02:
				frame, err = frames.ParseConnectionCloseFrame(r)
				if err != nil {
					err = qerr.Error(qerr.InvalidConnectionCloseData, err.Error())
				}
			case 0x03:
				frame, err = frames.ParseGoawayFrame(r)
				if err != nil {
					err = qerr.Error(qerr.InvalidGoawayData, err.Error())
				}
			case 0x04:
				frame, err = frames.ParseWindowUpdateFrame(r)
				if err != nil {
					err = qerr.Error(qerr.InvalidWindowUpdateData, err.Error())
				}
			case 0x05:
				frame, err = frames.ParseBlockedFrame(r)
				if err != nil {
					err = qerr.Error(qerr.InvalidBlockedData, err.Error())
				}
			case 0x06:
				frame, err = frames.ParseStopWaitingFrame(r, hdr.PacketNumber, hdr.PacketNumberLen, u.version)
				if err != nil {
					err = qerr.Error(qerr.InvalidStopWaitingData, err.Error())
				}
			case 0x07:
				frame, err = frames.ParsePingFrame(r)
			default:
				err = qerr.Error(qerr.InvalidFrameData, fmt.Sprintf("unknown type byte 0x%x", typeByte))
			}
		}
		if err != nil {
			return nil, err
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
