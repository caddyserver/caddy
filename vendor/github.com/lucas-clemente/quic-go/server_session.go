package quic

import (
	"fmt"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

type serverSession struct {
	quicSession

	config *Config

	logger utils.Logger
}

var _ packetHandler = &serverSession{}

func newServerSession(sess quicSession, config *Config, logger utils.Logger) packetHandler {
	return &serverSession{
		quicSession: sess,
		config:      config,
		logger:      logger,
	}
}

func (s *serverSession) handlePacket(p *receivedPacket) {
	if err := s.handlePacketImpl(p); err != nil {
		s.logger.Debugf("error handling packet from %s: %s", p.remoteAddr, err)
	}
}

func (s *serverSession) handlePacketImpl(p *receivedPacket) error {
	hdr := p.header
	// ignore all Public Reset packets
	if hdr.ResetFlag {
		return fmt.Errorf("Received unexpected Public Reset for connection %s", hdr.DestConnectionID)
	}

	// Probably an old packet that was sent by the client before the version was negotiated.
	// It is safe to drop it.
	if (hdr.VersionFlag || hdr.IsLongHeader) && hdr.Version != s.quicSession.GetVersion() {
		return nil
	}

	if hdr.IsLongHeader {
		switch hdr.Type {
		case protocol.PacketTypeHandshake, protocol.PacketType0RTT: // 0-RTT accepted for gQUIC 44
			// nothing to do here. Packet will be passed to the session.
		default:
			// Note that this also drops 0-RTT packets.
			return fmt.Errorf("Received unsupported packet type: %s", hdr.Type)
		}
	}

	s.quicSession.handlePacket(p)
	return nil
}

func (s *serverSession) GetPerspective() protocol.Perspective {
	return protocol.PerspectiveServer
}
