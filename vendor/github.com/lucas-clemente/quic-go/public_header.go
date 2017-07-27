package quic

import (
	"bytes"
	"errors"

	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
)

var (
	errPacketNumberLenNotSet             = errors.New("PublicHeader: PacketNumberLen not set")
	errResetAndVersionFlagSet            = errors.New("PublicHeader: Reset Flag and Version Flag should not be set at the same time")
	errReceivedTruncatedConnectionID     = qerr.Error(qerr.InvalidPacketHeader, "receiving packets with truncated ConnectionID is not supported")
	errInvalidConnectionID               = qerr.Error(qerr.InvalidPacketHeader, "connection ID cannot be 0")
	errGetLengthNotForVersionNegotiation = errors.New("PublicHeader: GetLength cannot be called for VersionNegotiation packets")
)

// The PublicHeader of a QUIC packet. Warning: This struct should not be considered stable and will change soon.
type PublicHeader struct {
	Raw                  []byte
	ConnectionID         protocol.ConnectionID
	VersionFlag          bool
	ResetFlag            bool
	TruncateConnectionID bool
	PacketNumberLen      protocol.PacketNumberLen
	PacketNumber         protocol.PacketNumber
	VersionNumber        protocol.VersionNumber   // VersionNumber sent by the client
	SupportedVersions    []protocol.VersionNumber // VersionNumbers sent by the server
	DiversificationNonce []byte
}

// Write writes a public header. Warning: This API should not be considered stable and will change soon.
func (h *PublicHeader) Write(b *bytes.Buffer, version protocol.VersionNumber, pers protocol.Perspective) error {
	publicFlagByte := uint8(0x00)

	if h.VersionFlag && h.ResetFlag {
		return errResetAndVersionFlagSet
	}

	if h.VersionFlag {
		publicFlagByte |= 0x01
	}
	if h.ResetFlag {
		publicFlagByte |= 0x02
	}
	if !h.TruncateConnectionID {
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

	if !h.TruncateConnectionID {
		utils.WriteUint64(b, uint64(h.ConnectionID))
	}

	if h.VersionFlag && pers == protocol.PerspectiveClient {
		utils.WriteUint32(b, protocol.VersionNumberToTag(h.VersionNumber))
	}

	if len(h.DiversificationNonce) > 0 {
		b.Write(h.DiversificationNonce)
	}

	// if we're a server, and the VersionFlag is set, we must not include anything else in the packet
	if !h.hasPacketNumber(pers) {
		return nil
	}

	if h.PacketNumberLen != protocol.PacketNumberLen1 && h.PacketNumberLen != protocol.PacketNumberLen2 && h.PacketNumberLen != protocol.PacketNumberLen4 && h.PacketNumberLen != protocol.PacketNumberLen6 {
		return errPacketNumberLenNotSet
	}

	switch h.PacketNumberLen {
	case protocol.PacketNumberLen1:
		b.WriteByte(uint8(h.PacketNumber))
	case protocol.PacketNumberLen2:
		utils.WriteUint16(b, uint16(h.PacketNumber))
	case protocol.PacketNumberLen4:
		utils.WriteUint32(b, uint32(h.PacketNumber))
	case protocol.PacketNumberLen6:
		utils.WriteUint48(b, uint64(h.PacketNumber))
	default:
		return errPacketNumberLenNotSet
	}

	return nil
}

// ParsePublicHeader parses a QUIC packet's public header.
// The packetSentBy is the perspective of the peer that sent this PublicHeader, i.e. if we're the server, packetSentBy should be PerspectiveClient.
// Warning: This API should not be considered stable and will change soon.
func ParsePublicHeader(b *bytes.Reader, packetSentBy protocol.Perspective) (*PublicHeader, error) {
	header := &PublicHeader{}

	// First byte
	publicFlagByte, err := b.ReadByte()
	if err != nil {
		return nil, err
	}
	header.VersionFlag = publicFlagByte&0x01 > 0
	header.ResetFlag = publicFlagByte&0x02 > 0

	// TODO: activate this check once Chrome sends the correct value
	// see https://github.com/lucas-clemente/quic-go/issues/232
	// if publicFlagByte&0x04 > 0 {
	// 	return nil, errors.New("diversification nonces should only be sent by servers")
	// }

	header.TruncateConnectionID = publicFlagByte&0x08 == 0
	if header.TruncateConnectionID && packetSentBy == protocol.PerspectiveClient {
		return nil, errReceivedTruncatedConnectionID
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
	if !header.TruncateConnectionID {
		var connID uint64
		connID, err = utils.ReadUint64(b)
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
			// this Read can never return an EOF for a valid packet, since the diversification nonce is followed by the packet number
			_, err = b.Read(header.DiversificationNonce)
			if err != nil {
				return nil, err
			}
		}
	}

	// Version (optional)
	if !header.ResetFlag {
		if header.VersionFlag {
			if packetSentBy == protocol.PerspectiveClient {
				var versionTag uint32
				versionTag, err = utils.ReadUint32(b)
				if err != nil {
					return nil, err
				}
				header.VersionNumber = protocol.VersionTagToNumber(versionTag)
			} else { // parse the version negotiaton packet
				if b.Len()%4 != 0 {
					return nil, qerr.InvalidVersionNegotiationPacket
				}
				header.SupportedVersions = make([]protocol.VersionNumber, 0)
				for {
					var versionTag uint32
					versionTag, err = utils.ReadUint32(b)
					if err != nil {
						break
					}
					v := protocol.VersionTagToNumber(versionTag)
					header.SupportedVersions = append(header.SupportedVersions, v)
				}
			}
		}
	}

	// Packet number
	if header.hasPacketNumber(packetSentBy) {
		packetNumber, err := utils.ReadUintN(b, uint8(header.PacketNumberLen))
		if err != nil {
			return nil, err
		}
		header.PacketNumber = protocol.PacketNumber(packetNumber)
	}

	return header, nil
}

// GetLength gets the length of the publicHeader in bytes.
// It can only be called for regular packets.
func (h *PublicHeader) GetLength(pers protocol.Perspective) (protocol.ByteCount, error) {
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

	if !h.TruncateConnectionID {
		length += 8 // 8 bytes for the connection ID
	}

	// Version Number in packets sent by the client
	if h.VersionFlag {
		length += 4
	}

	length += protocol.ByteCount(len(h.DiversificationNonce))

	return length, nil
}

// hasPacketNumber determines if this PublicHeader will contain a packet number
// this depends on the ResetFlag, the VersionFlag and who sent the packet
func (h *PublicHeader) hasPacketNumber(packetSentBy protocol.Perspective) bool {
	if h.ResetFlag {
		return false
	}
	if h.VersionFlag && packetSentBy == protocol.PerspectiveServer {
		return false
	}
	return true
}
