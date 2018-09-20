package wire

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
)

// ParseNextFrame parses the next frame
// It skips PADDING frames.
func ParseNextFrame(r *bytes.Reader, hdr *Header, v protocol.VersionNumber) (Frame, error) {
	for r.Len() != 0 {
		typeByte, _ := r.ReadByte()
		if typeByte == 0x0 { // PADDING frame
			continue
		}
		r.UnreadByte()

		if !v.UsesIETFFrameFormat() {
			return parseGQUICFrame(r, typeByte, hdr, v)
		}
		return parseIETFFrame(r, typeByte, v)
	}
	return nil, nil
}

func parseIETFFrame(r *bytes.Reader, typeByte byte, v protocol.VersionNumber) (Frame, error) {
	var frame Frame
	var err error
	if typeByte&0xf8 == 0x10 {
		frame, err = parseStreamFrame(r, v)
		if err != nil {
			err = qerr.Error(qerr.InvalidStreamData, err.Error())
		}
		return frame, err
	}
	// TODO: implement all IETF QUIC frame types
	switch typeByte {
	case 0x1:
		frame, err = parseRstStreamFrame(r, v)
		if err != nil {
			err = qerr.Error(qerr.InvalidRstStreamData, err.Error())
		}
	case 0x2:
		frame, err = parseConnectionCloseFrame(r, v)
		if err != nil {
			err = qerr.Error(qerr.InvalidConnectionCloseData, err.Error())
		}
	case 0x4:
		frame, err = parseMaxDataFrame(r, v)
		if err != nil {
			err = qerr.Error(qerr.InvalidWindowUpdateData, err.Error())
		}
	case 0x5:
		frame, err = parseMaxStreamDataFrame(r, v)
		if err != nil {
			err = qerr.Error(qerr.InvalidWindowUpdateData, err.Error())
		}
	case 0x6:
		frame, err = parseMaxStreamIDFrame(r, v)
		if err != nil {
			err = qerr.Error(qerr.InvalidFrameData, err.Error())
		}
	case 0x7:
		frame, err = parsePingFrame(r, v)
	case 0x8:
		frame, err = parseBlockedFrame(r, v)
		if err != nil {
			err = qerr.Error(qerr.InvalidBlockedData, err.Error())
		}
	case 0x9:
		frame, err = parseStreamBlockedFrame(r, v)
		if err != nil {
			err = qerr.Error(qerr.InvalidBlockedData, err.Error())
		}
	case 0xa:
		frame, err = parseStreamIDBlockedFrame(r, v)
		if err != nil {
			err = qerr.Error(qerr.InvalidFrameData, err.Error())
		}
	case 0xc:
		frame, err = parseStopSendingFrame(r, v)
		if err != nil {
			err = qerr.Error(qerr.InvalidFrameData, err.Error())
		}
	case 0xd:
		frame, err = parseAckFrame(r, v)
		if err != nil {
			err = qerr.Error(qerr.InvalidAckData, err.Error())
		}
	case 0xe:
		frame, err = parsePathChallengeFrame(r, v)
		if err != nil {
			err = qerr.Error(qerr.InvalidFrameData, err.Error())
		}
	case 0xf:
		frame, err = parsePathResponseFrame(r, v)
		if err != nil {
			err = qerr.Error(qerr.InvalidFrameData, err.Error())
		}
	case 0x1a:
		frame, err = parseAckEcnFrame(r, v)
		if err != nil {
			err = qerr.Error(qerr.InvalidAckData, err.Error())
		}
	default:
		err = qerr.Error(qerr.InvalidFrameData, fmt.Sprintf("unknown type byte 0x%x", typeByte))
	}
	return frame, err
}

func parseGQUICFrame(r *bytes.Reader, typeByte byte, hdr *Header, v protocol.VersionNumber) (Frame, error) {
	var frame Frame
	var err error
	if typeByte&0x80 == 0x80 {
		frame, err = parseStreamFrame(r, v)
		if err != nil {
			err = qerr.Error(qerr.InvalidStreamData, err.Error())
		}
		return frame, err
	} else if typeByte&0xc0 == 0x40 {
		frame, err = parseAckFrame(r, v)
		if err != nil {
			err = qerr.Error(qerr.InvalidAckData, err.Error())
		}
		return frame, err
	}
	switch typeByte {
	case 0x1:
		frame, err = parseRstStreamFrame(r, v)
		if err != nil {
			err = qerr.Error(qerr.InvalidRstStreamData, err.Error())
		}
	case 0x2:
		frame, err = parseConnectionCloseFrame(r, v)
		if err != nil {
			err = qerr.Error(qerr.InvalidConnectionCloseData, err.Error())
		}
	case 0x3:
		frame, err = parseGoawayFrame(r, v)
		if err != nil {
			err = qerr.Error(qerr.InvalidGoawayData, err.Error())
		}
	case 0x4:
		frame, err = parseWindowUpdateFrame(r, v)
		if err != nil {
			err = qerr.Error(qerr.InvalidWindowUpdateData, err.Error())
		}
	case 0x5:
		frame, err = parseBlockedFrameLegacy(r, v)
		if err != nil {
			err = qerr.Error(qerr.InvalidBlockedData, err.Error())
		}
	case 0x6:
		if !v.UsesStopWaitingFrames() {
			err = errors.New("STOP_WAITING frames not supported by this QUIC version")
			break
		}
		frame, err = parseStopWaitingFrame(r, hdr.PacketNumber, hdr.PacketNumberLen, v)
		if err != nil {
			err = qerr.Error(qerr.InvalidStopWaitingData, err.Error())
		}
	case 0x7:
		frame, err = parsePingFrame(r, v)
	default:
		err = qerr.Error(qerr.InvalidFrameData, fmt.Sprintf("unknown type byte 0x%x", typeByte))
	}
	return frame, err
}
