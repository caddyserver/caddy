package wire

import (
	"bytes"
	"crypto/rand"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

// ComposeGQUICVersionNegotiation composes a Version Negotiation Packet for gQUIC
func ComposeGQUICVersionNegotiation(connID protocol.ConnectionID, versions []protocol.VersionNumber) []byte {
	fullReply := &bytes.Buffer{}
	ph := Header{
		ConnectionID:         connID,
		PacketNumber:         1,
		VersionFlag:          true,
		IsVersionNegotiation: true,
	}
	if err := ph.writePublicHeader(fullReply, protocol.PerspectiveServer, protocol.VersionWhatever); err != nil {
		utils.Errorf("error composing version negotiation packet: %s", err.Error())
		return nil
	}
	writeVersions(fullReply, versions)
	return fullReply.Bytes()
}

// ComposeVersionNegotiation composes a Version Negotiation according to the IETF draft
func ComposeVersionNegotiation(
	connID protocol.ConnectionID,
	pn protocol.PacketNumber,
	versions []protocol.VersionNumber,
) []byte {
	fullReply := &bytes.Buffer{}
	r := make([]byte, 1)
	_, _ = rand.Read(r) // ignore the error here. It is not critical to have perfect random here.
	h := Header{
		IsLongHeader:         true,
		Type:                 protocol.PacketType(r[0] | 0x80),
		ConnectionID:         connID,
		PacketNumber:         pn,
		Version:              0,
		IsVersionNegotiation: true,
	}
	if err := h.writeHeader(fullReply); err != nil {
		utils.Errorf("error composing version negotiation packet: %s", err.Error())
		return nil
	}
	writeVersions(fullReply, versions)
	return fullReply.Bytes()
}

// writeVersions writes the versions for a Version Negotiation Packet.
// It inserts one reserved version number at a random position.
func writeVersions(buf *bytes.Buffer, supported []protocol.VersionNumber) {
	for _, v := range protocol.GetGreasedVersions(supported) {
		utils.BigEndian.WriteUint32(buf, uint32(v))
	}
}
