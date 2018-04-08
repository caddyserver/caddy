package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

// Header is the header of a QUIC packet.
// It contains fields that are only needed for the gQUIC Public Header and the IETF draft Header.
type Header struct {
	Raw              []byte
	ConnectionID     protocol.ConnectionID
	OmitConnectionID bool
	PacketNumberLen  protocol.PacketNumberLen
	PacketNumber     protocol.PacketNumber
	Version          protocol.VersionNumber // VersionNumber sent by the client

	IsVersionNegotiation bool
	SupportedVersions    []protocol.VersionNumber // Version Number sent in a Version Negotiation Packet by the server

	// only needed for the gQUIC Public Header
	VersionFlag          bool
	ResetFlag            bool
	DiversificationNonce []byte

	// only needed for the IETF Header
	Type         protocol.PacketType
	IsLongHeader bool
	KeyPhase     int

	// only needed for logging
	isPublicHeader bool
}

// ParseHeaderSentByServer parses the header for a packet that was sent by the server.
func ParseHeaderSentByServer(b *bytes.Reader, version protocol.VersionNumber) (*Header, error) {
	typeByte, err := b.ReadByte()
	if err != nil {
		return nil, err
	}
	_ = b.UnreadByte() // unread the type byte

	var isPublicHeader bool
	if typeByte&0x80 > 0 { // gQUIC always has 0x80 unset. IETF Long Header or Version Negotiation
		isPublicHeader = false
	} else if typeByte&0xcf == 0x9 { // gQUIC Version Negotiation Packet
		isPublicHeader = true
	} else {
		// the client knows the version that this packet was sent with
		isPublicHeader = !version.UsesTLS()
	}

	return parsePacketHeader(b, protocol.PerspectiveServer, isPublicHeader)
}

// ParseHeaderSentByClient parses the header for a packet that was sent by the client.
func ParseHeaderSentByClient(b *bytes.Reader) (*Header, error) {
	typeByte, err := b.ReadByte()
	if err != nil {
		return nil, err
	}
	_ = b.UnreadByte() // unread the type byte

	// In an IETF QUIC packet header
	// * either 0x80 is set (for the Long Header)
	// * or 0x8 is unset (for the Short Header)
	// In a gQUIC Public Header
	// * 0x80 is always unset and
	// * and 0x8 is always set (this is the Connection ID flag, which the client always sets)
	isPublicHeader := typeByte&0x88 == 0x8
	return parsePacketHeader(b, protocol.PerspectiveClient, isPublicHeader)
}

func parsePacketHeader(b *bytes.Reader, sentBy protocol.Perspective, isPublicHeader bool) (*Header, error) {
	// This is a gQUIC Public Header.
	if isPublicHeader {
		hdr, err := parsePublicHeader(b, sentBy)
		if err != nil {
			return nil, err
		}
		hdr.isPublicHeader = true // save that this is a Public Header, so we can log it correctly later
		return hdr, nil
	}
	return parseHeader(b, sentBy)
}

// Write writes the Header.
func (h *Header) Write(b *bytes.Buffer, pers protocol.Perspective, version protocol.VersionNumber) error {
	if !version.UsesTLS() {
		h.isPublicHeader = true // save that this is a Public Header, so we can log it correctly later
		return h.writePublicHeader(b, pers, version)
	}
	return h.writeHeader(b)
}

// GetLength determines the length of the Header.
func (h *Header) GetLength(pers protocol.Perspective, version protocol.VersionNumber) (protocol.ByteCount, error) {
	if !version.UsesTLS() {
		return h.getPublicHeaderLength(pers)
	}
	return h.getHeaderLength()
}

// Log logs the Header
func (h *Header) Log() {
	if h.isPublicHeader {
		h.logPublicHeader()
	} else {
		h.logHeader()
	}
}
