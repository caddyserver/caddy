package quic

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"

	"github.com/bifurcation/mint"
	"github.com/lucas-clemente/quic-go/internal/crypto"
	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"github.com/lucas-clemente/quic-go/qerr"
)

type nullAEAD struct {
	aead crypto.AEAD
}

var _ quicAEAD = &nullAEAD{}

func (n *nullAEAD) Open(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, protocol.EncryptionLevel, error) {
	data, err := n.aead.Open(dst, src, packetNumber, associatedData)
	return data, protocol.EncryptionUnencrypted, err
}

type serverTLS struct {
	conn              net.PacketConn
	config            *Config
	supportedVersions []protocol.VersionNumber
	mintConf          *mint.Config
	cookieProtector   mint.CookieProtector
	params            *handshake.TransportParameters
	newMintConn       func(*handshake.CryptoStreamConn, protocol.VersionNumber) (handshake.MintTLS, <-chan handshake.TransportParameters, error)

	sessionChan chan<- packetHandler
}

func newServerTLS(
	conn net.PacketConn,
	config *Config,
	cookieHandler *handshake.CookieHandler,
	tlsConf *tls.Config,
) (*serverTLS, <-chan packetHandler, error) {
	mconf, err := tlsToMintConfig(tlsConf, protocol.PerspectiveServer)
	if err != nil {
		return nil, nil, err
	}
	mconf.RequireCookie = true
	cs, err := mint.NewDefaultCookieProtector()
	if err != nil {
		return nil, nil, err
	}
	mconf.CookieProtector = cs
	mconf.CookieHandler = cookieHandler

	sessionChan := make(chan packetHandler)
	s := &serverTLS{
		conn:              conn,
		config:            config,
		supportedVersions: config.Versions,
		mintConf:          mconf,
		sessionChan:       sessionChan,
		params: &handshake.TransportParameters{
			StreamFlowControlWindow:     protocol.ReceiveStreamFlowControlWindow,
			ConnectionFlowControlWindow: protocol.ReceiveConnectionFlowControlWindow,
			MaxStreams:                  protocol.MaxIncomingStreams,
			IdleTimeout:                 config.IdleTimeout,
		},
	}
	s.newMintConn = s.newMintConnImpl
	return s, sessionChan, nil
}

func (s *serverTLS) HandleInitial(remoteAddr net.Addr, hdr *wire.Header, data []byte) {
	utils.Debugf("Received a Packet. Handling it statelessly.")
	sess, err := s.handleInitialImpl(remoteAddr, hdr, data)
	if err != nil {
		utils.Errorf("Error occured handling initial packet: %s", err)
		return
	}
	if sess == nil { // a stateless reset was done
		return
	}
	s.sessionChan <- sess
}

// will be set to s.newMintConn by the constructor
func (s *serverTLS) newMintConnImpl(bc *handshake.CryptoStreamConn, v protocol.VersionNumber) (handshake.MintTLS, <-chan handshake.TransportParameters, error) {
	extHandler := handshake.NewExtensionHandlerServer(s.params, s.config.Versions, v)
	conf := s.mintConf.Clone()
	conf.ExtensionHandler = extHandler
	return newMintController(bc, conf, protocol.PerspectiveServer), extHandler.GetPeerParams(), nil
}

func (s *serverTLS) sendConnectionClose(remoteAddr net.Addr, clientHdr *wire.Header, aead crypto.AEAD, closeErr error) error {
	ccf := &wire.ConnectionCloseFrame{
		ErrorCode:    qerr.HandshakeFailed,
		ReasonPhrase: closeErr.Error(),
	}
	replyHdr := &wire.Header{
		IsLongHeader: true,
		Type:         protocol.PacketTypeHandshake,
		ConnectionID: clientHdr.ConnectionID, // echo the client's connection ID
		PacketNumber: 1,                      // random packet number
		Version:      clientHdr.Version,
	}
	data, err := packUnencryptedPacket(aead, replyHdr, ccf, protocol.PerspectiveServer)
	if err != nil {
		return err
	}
	_, err = s.conn.WriteTo(data, remoteAddr)
	return err
}

func (s *serverTLS) handleInitialImpl(remoteAddr net.Addr, hdr *wire.Header, data []byte) (packetHandler, error) {
	if len(hdr.Raw)+len(data) < protocol.MinInitialPacketSize {
		return nil, errors.New("dropping too small Initial packet")
	}
	// check version, if not matching send VNP
	if !protocol.IsSupportedVersion(s.supportedVersions, hdr.Version) {
		utils.Debugf("Client offered version %s, sending VersionNegotiationPacket", hdr.Version)
		_, err := s.conn.WriteTo(wire.ComposeVersionNegotiation(hdr.ConnectionID, hdr.PacketNumber, s.supportedVersions), remoteAddr)
		return nil, err
	}

	// unpack packet and check stream frame contents
	aead, err := crypto.NewNullAEAD(protocol.PerspectiveServer, hdr.ConnectionID, hdr.Version)
	if err != nil {
		return nil, err
	}
	frame, err := unpackInitialPacket(aead, hdr, data, hdr.Version)
	if err != nil {
		utils.Debugf("Error unpacking initial packet: %s", err)
		return nil, nil
	}
	sess, err := s.handleUnpackedInitial(remoteAddr, hdr, frame, aead)
	if err != nil {
		if ccerr := s.sendConnectionClose(remoteAddr, hdr, aead, err); ccerr != nil {
			utils.Debugf("Error sending CONNECTION_CLOSE: ", ccerr)
		}
		return nil, err
	}
	return sess, nil
}

func (s *serverTLS) handleUnpackedInitial(remoteAddr net.Addr, hdr *wire.Header, frame *wire.StreamFrame, aead crypto.AEAD) (packetHandler, error) {
	version := hdr.Version
	bc := handshake.NewCryptoStreamConn(remoteAddr)
	bc.AddDataForReading(frame.Data)
	tls, paramsChan, err := s.newMintConn(bc, version)
	if err != nil {
		return nil, err
	}
	alert := tls.Handshake()
	if alert == mint.AlertStatelessRetry {
		// the HelloRetryRequest was written to the bufferConn
		// Take that data and write send a Retry packet
		replyHdr := &wire.Header{
			IsLongHeader: true,
			Type:         protocol.PacketTypeRetry,
			ConnectionID: hdr.ConnectionID, // echo the client's connection ID
			PacketNumber: hdr.PacketNumber, // echo the client's packet number
			Version:      version,
		}
		f := &wire.StreamFrame{
			StreamID: version.CryptoStreamID(),
			Data:     bc.GetDataForWriting(),
		}
		data, err := packUnencryptedPacket(aead, replyHdr, f, protocol.PerspectiveServer)
		if err != nil {
			return nil, err
		}
		_, err = s.conn.WriteTo(data, remoteAddr)
		return nil, err
	}
	if alert != mint.AlertNoAlert {
		return nil, alert
	}
	if tls.State() != mint.StateServerNegotiated {
		return nil, fmt.Errorf("Expected mint state to be %s, got %s", mint.StateServerNegotiated, tls.State())
	}
	if alert := tls.Handshake(); alert != mint.AlertNoAlert {
		return nil, alert
	}
	if tls.State() != mint.StateServerWaitFlight2 {
		return nil, fmt.Errorf("Expected mint state to be %s, got %s", mint.StateServerWaitFlight2, tls.State())
	}
	params := <-paramsChan
	sess, err := newTLSServerSession(
		&conn{pconn: s.conn, currentAddr: remoteAddr},
		hdr.ConnectionID,         // TODO: we can use a server-chosen connection ID here
		protocol.PacketNumber(1), // TODO: use a random packet number here
		s.config,
		tls,
		bc,
		aead,
		&params,
		version,
	)
	if err != nil {
		return nil, err
	}
	cs := sess.getCryptoStream()
	cs.setReadOffset(frame.DataLen())
	bc.SetStream(cs)
	return sess, nil
}
