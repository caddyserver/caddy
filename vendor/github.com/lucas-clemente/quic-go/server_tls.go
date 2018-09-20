package quic

import (
	"bytes"
	"crypto/tls"
	"errors"
	"net"

	"github.com/bifurcation/mint"
	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type tlsSession struct {
	connID protocol.ConnectionID
	sess   quicSession
}

type serverTLS struct {
	conn            net.PacketConn
	config          *Config
	mintConf        *mint.Config
	params          *handshake.TransportParameters
	cookieGenerator *handshake.CookieGenerator

	newSession func(connection, sessionRunner, protocol.ConnectionID, protocol.ConnectionID, protocol.ConnectionID, protocol.PacketNumber, *Config, *mint.Config, *handshake.TransportParameters, utils.Logger, protocol.VersionNumber) (quicSession, error)

	sessionRunner sessionRunner
	sessionChan   chan<- tlsSession

	logger utils.Logger
}

func newServerTLS(
	conn net.PacketConn,
	config *Config,
	runner sessionRunner,
	tlsConf *tls.Config,
	logger utils.Logger,
) (*serverTLS, <-chan tlsSession, error) {
	cookieGenerator, err := handshake.NewCookieGenerator()
	if err != nil {
		return nil, nil, err
	}
	params := &handshake.TransportParameters{
		StreamFlowControlWindow:     protocol.ReceiveStreamFlowControlWindow,
		ConnectionFlowControlWindow: protocol.ReceiveConnectionFlowControlWindow,
		IdleTimeout:                 config.IdleTimeout,
		MaxBidiStreams:              uint16(config.MaxIncomingStreams),
		MaxUniStreams:               uint16(config.MaxIncomingUniStreams),
		DisableMigration:            true,
		// TODO(#855): generate a real token
		StatelessResetToken: bytes.Repeat([]byte{42}, 16),
	}
	mconf, err := tlsToMintConfig(tlsConf, protocol.PerspectiveServer)
	if err != nil {
		return nil, nil, err
	}

	sessionChan := make(chan tlsSession)
	s := &serverTLS{
		conn:            conn,
		config:          config,
		mintConf:        mconf,
		sessionRunner:   runner,
		sessionChan:     sessionChan,
		cookieGenerator: cookieGenerator,
		params:          params,
		newSession:      newTLSServerSession,
		logger:          logger,
	}
	return s, sessionChan, nil
}

func (s *serverTLS) HandleInitial(p *receivedPacket) {
	// TODO: add a check that DestConnID == SrcConnID
	s.logger.Debugf("<- Received Initial packet.")
	sess, connID, err := s.handleInitialImpl(p)
	if err != nil {
		s.logger.Errorf("Error occurred handling initial packet: %s", err)
		return
	}
	if sess == nil { // a stateless reset was done
		return
	}
	s.sessionChan <- tlsSession{
		connID: connID,
		sess:   sess,
	}
}

func (s *serverTLS) handleInitialImpl(p *receivedPacket) (quicSession, protocol.ConnectionID, error) {
	hdr := p.header
	if len(hdr.Token) == 0 && hdr.DestConnectionID.Len() < protocol.MinConnectionIDLenInitial {
		return nil, nil, errors.New("dropping Initial packet with too short connection ID")
	}
	if len(hdr.Raw)+len(p.data) < protocol.MinInitialPacketSize {
		return nil, nil, errors.New("dropping too small Initial packet")
	}

	var cookie *handshake.Cookie
	if len(hdr.Token) > 0 {
		c, err := s.cookieGenerator.DecodeToken(hdr.Token)
		if err == nil {
			cookie = c
		}
	}
	if !s.config.AcceptCookie(p.remoteAddr, cookie) {
		// Log the Initial packet now.
		// If no Retry is sent, the packet will be logged by the session.
		p.header.Log(s.logger)
		return nil, nil, s.sendRetry(p.remoteAddr, hdr)
	}

	extHandler := handshake.NewExtensionHandlerServer(s.params, s.config.Versions, hdr.Version, s.logger)
	mconf := s.mintConf.Clone()
	mconf.ExtensionHandler = extHandler

	// A server is allowed to perform multiple Retries.
	// It doesn't make much sense, but it's something that our API allows.
	// In that case it must use a source connection ID of at least 8 bytes.
	connID, err := protocol.GenerateConnectionID(s.config.ConnectionIDLength)
	if err != nil {
		return nil, nil, err
	}
	s.logger.Debugf("Changing connection ID to %s.", connID)
	sess, err := s.newSession(
		&conn{pconn: s.conn, currentAddr: p.remoteAddr},
		s.sessionRunner,
		hdr.DestConnectionID,
		hdr.SrcConnectionID,
		connID,
		1,
		s.config,
		mconf,
		s.params,
		s.logger,
		hdr.Version,
	)
	if err != nil {
		return nil, nil, err
	}
	go sess.run()
	sess.handlePacket(p)
	return sess, connID, nil
}

func (s *serverTLS) sendRetry(remoteAddr net.Addr, hdr *wire.Header) error {
	token, err := s.cookieGenerator.NewToken(remoteAddr)
	if err != nil {
		return err
	}
	connID, err := protocol.GenerateConnectionIDForInitial()
	if err != nil {
		return err
	}
	replyHdr := &wire.Header{
		IsLongHeader:         true,
		Type:                 protocol.PacketTypeRetry,
		Version:              hdr.Version,
		SrcConnectionID:      connID,
		DestConnectionID:     hdr.SrcConnectionID,
		OrigDestConnectionID: hdr.DestConnectionID,
		Token:                token,
	}
	s.logger.Debugf("Changing connection ID to %s.\n-> Sending Retry", connID)
	replyHdr.Log(s.logger)
	buf := &bytes.Buffer{}
	if err := replyHdr.Write(buf, protocol.PerspectiveServer, hdr.Version); err != nil {
		return err
	}
	if _, err := s.conn.WriteTo(buf.Bytes(), remoteAddr); err != nil {
		s.logger.Debugf("Error sending Retry: %s", err)
	}
	return nil
}
