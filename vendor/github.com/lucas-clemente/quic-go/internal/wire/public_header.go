package wire

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/qerr"
)

var (
	errResetAndVersionFlagSet            = errors.New("PublicHeader: Reset Flag and Version Flag should not be set at the same time")
	errReceivedOmittedConnectionID       = qerr.Error(qerr.InvalidPacketHeader, "receiving packets with omitted ConnectionID is not supported")
	errInvalidConnectionID               = qerr.Error(qerr.InvalidPacketHeader, "connection ID cannot be 0")
	errGetLengthNotForVersionNegotiation = errors.New("PublicHeader: GetLength cannot be called for VersionNegotiation packets")
)

// writePublicHeader writes a Public Header.
func (h *Header) writePublicHeader(b *bytes.Buffer, pers protocol.Perspective, _ protocol.VersionNumber) error {
	if h.VersionFlag && h.ResetFlag {
		return errResetAndVersionFlagSet
	}

	publicFlagByte := uint8(0x00)
	if h.VersionFlag {
		publicFlagByte |= 0x01
	}
	if h.ResetFlag {
		publicFlagByte |= 0x02
	}
	if !h.OmitConnectionID {
		publicFlagByte |= 0x08
	}
	if len(h.DiversificationNonce) > 0 {
		if len(h.DiversificationNonce) != 32 {
			return errors.New("invalid diversification nonce length")
		}
		publicFlagByte |= 0x04
	}
	// only set PacketNumberLen bits if a packet number will be written
	if h.hasPacketNumber(pers) {
		switch h.PacketNumberLen {
		case protocol.PacketNumberLen1:
			publicFlagByte |= 0x00
		case protocol.PacketNumberLen2:
			publicFlagByte |= 0x10
		case protocol.PacketNumberLen4:
			publicFlagByte |= 0x20
		case protocol.PacketNumberLen6:
			publicFlagByte |= 0x30
		}
	}
	b.WriteByte(publicFlagByte)

	if !h.OmitConnectionID {
		utils.BigEndian.WriteUint64(b, uint64(h.ConnectionID))
	}
	if h.VersionFlag && pers == protocol.PerspectiveClient {
		utils.BigEndian.WriteUint32(b, uint32(h.Version))
	}
	if len(h.DiversificationNonce) > 0 {
		b.Write(h.DiversificationNonce)
	}
	// if we're a server, and the VersionFlag is set, we must not include anything else in the packet
	if !h.hasPacketNumber(pers) {
		return nil
	}

	switch h.PacketNumberLen {
	case protocol.PacketNumberLen1:
		b.WriteByte(uint8(h.PacketNumber))
	case protocol.PacketNumberLen2:
		utils.BigEndian.WriteUint16(b, uint16(h.PacketNumber))
	case protocol.PacketNumberLen4:
		utils.BigEndian.WriteUint32(b, uint32(h.PacketNumber))
	case protocol.PacketNumberLen6:
		utils.BigEndian.WriteUint48(b, uint64(h.PacketNumber)&(1<<48-1))
	default:
		return errors.New("PublicHeader: PacketNumberLen not set")
	}

	return nil
}

// parsePublicHeader parses a QUIC packet's Public Header.
// The packetSentBy is the perspective of the peer that sent this PublicHeader, i.e. if we're the server, packetSentBy should be PerspectiveClient.
func parsePublicHeader(b *bytes.Reader, packetSentBy protocol.Perspective) (*Header, error) {
	header := &Header{}

	// First byte
	publicFlagByte, err := b.ReadByte()
	if err != nil {
		return nil, err
	}
	header.ResetFlag = publicFlagByte&0x02 > 0
	header.VersionFlag = publicFlagByte&0x01 > 0

	// TODO: activate this check once Chrome sends the correct value
	// see https://github.com/lucas-clemente/quic-go/issues/232
	// if publicFlagByte&0x04 > 0 {
	// 	return nil, errors.New("diversification nonces should only be sent by servers")
	// }

	header.OmitConnectionID = publicFlagByte&0x08 == 0
	if header.OmitConnectionID && packetSentBy == protocol.PerspectiveClient {
		return nil, errReceivedOmittedConnectionID
	}
	if header.hasPacketNumber(packetSentBy) {
		switch publicFlagByte & 0x30 {
		case 0x30:
			header.PacketNumberLen = protocol.PacketNumberLen6
		case 0x20:
			header.PacketNumberLen = protocol.PacketNumberLen4
		case 0x10:
			header.PacketNumberLen = protocol.PacketNumberLen2
		case 0x00:
			header.PacketNumberLen = protocol.PacketNumberLen1
		}
	}

	// Connection ID
	if !header.OmitConnectionID {
		var connID uint64
		connID, err = utils.BigEndian.ReadUint64(b)
		if err != nil {
			return nil, err
		}
		header.ConnectionID = protocol.ConnectionID(connID)
		if header.ConnectionID == 0 {
			return nil, errInvalidConnectionID
		}
	}

	if packetSentBy == protocol.PerspectiveServer && publicFlagByte&0x04 > 0 {
		// TODO: remove the if once the Google servers send the correct value
		// assume that a packet doesn't contain a diversification nonce if the version flag or the reset flag is set, no matter what the public flag says
		// see https://github.com/lucas-clemente/quic-go/issues/232
		if !header.VersionFlag && !header.ResetFlag {
			header.DiversificationNonce = make([]byte, 32)
			if _, err := io.ReadFull(b, header.DiversificationNonce); err != nil {
				return nil, err
			}
		}
	}

	// Version (optional)
	if !header.ResetFlag && header.VersionFlag {
		if packetSentBy == protocol.PerspectiveServer { // parse the version negotiaton packet
			if b.Len() == 0 {
				return nil, qerr.Error(qerr.InvalidVersionNegotiationPacket, "empty version list")
			}
			if b.Len()%4 != 0 {
				return nil, qerr.InvalidVersionNegotiationPacket
			}
			header.IsVersionNegotiation = true
			header.SupportedVersions = make([]protocol.VersionNumber, 0)
			for {
				var versionTag uint32
				versionTag, err = utils.BigEndian.ReadUint32(b)
				if err != nil {
					break
				}
				v := protocol.VersionNumber(versionTag)
				header.SupportedVersions = append(header.SupportedVersions, v)
			}
			// a version negotiation packet doesn't have a packet number
			return header, nil
		}
		// packet was sent by the client. Read the version number
		var versionTag uint32
		versionTag, err = utils.BigEndian.ReadUint32(b)
		if err != nil {
			return nil, err
		}
		header.Version = protocol.VersionNumber(versionTag)
	}

	// Packet number
	if header.hasPacketNumber(packetSentBy) {
		packetNumber, err := utils.BigEndian.ReadUintN(b, uint8(header.PacketNumberLen))
		if err != nil {
			return nil, err
		}
		header.PacketNumber = protocol.PacketNumber(packetNumber)
	}
	return header, nil
}

// getPublicHeaderLength gets the length of the publicHeader in bytes.
// It can only be called for regular packets.
func (h *Header) getPublicHeaderLength(pers protocol.Perspective) (protocol.ByteCount, error) {
	if h.VersionFlag && h.ResetFlag {
		return 0, errResetAndVersionFlagSet
	}
	if h.VersionFlag && pers == protocol.PerspectiveServer {
		return 0, errGetLengthNotForVersionNegotiation
	}

	length := protocol.ByteCount(1) // 1 byte for public flags
	if h.hasPacketNumber(pers) {
		if h.PacketNumberLen != protocol.PacketNumberLen1 && h.PacketNumberLen != protocol.PacketNumberLen2 && h.PacketNumberLen != protocol.PacketNumberLen4 && h.PacketNumberLen != protocol.PacketNumberLen6 {
			return 0, errPacketNumberLenNotSet
		}
		length += protocol.ByteCount(h.PacketNumberLen)
	}
	if !h.OmitConnectionID {
		length += 8 // 8 bytes for the connection ID
	}
	// Version Number in packets sent by the client
	if h.VersionFlag {
		length += 4
	}
	length += protocol.ByteCount(len(h.DiversificationNonce))
	return length, nil
}

// hasPacketNumber determines if this Public Header will contain a packet number
// this depends on the ResetFlag, the VersionFlag and who sent the packet
func (h *Header) hasPacketNumber(packetSentBy protocol.Perspective) bool {
	if h.ResetFlag {
		return false
	}
	if h.VersionFlag && packetSentBy == protocol.PerspectiveServer {
		return false
	}
	return true
}

func (h *Header) logPublicHeader() {
	connID := "(omitted)"
	if !h.OmitConnectionID {
		connID = fmt.Sprintf("%#x", h.ConnectionID)
	}
	ver := "(unset)"
	if h.Version != 0 {
		ver = fmt.Sprintf("%s", h.Version)
	}
	utils.Debugf("   Public Header{ConnectionID: %s, PacketNumber: %#x, PacketNumberLen: %d, Version: %s, DiversificationNonce: %#v}", connID, h.PacketNumber, h.PacketNumberLen, ver, h.DiversificationNonce)
}
