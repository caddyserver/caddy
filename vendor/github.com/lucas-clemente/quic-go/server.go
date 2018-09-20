package quic

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/internal/crypto"
	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

// packetHandler handles packets
type packetHandler interface {
	handlePacket(*receivedPacket)
	io.Closer
	destroy(error)
	GetVersion() protocol.VersionNumber
	GetPerspective() protocol.Perspective
}

type unknownPacketHandler interface {
	handlePacket(*receivedPacket)
	closeWithError(error) error
}

type packetHandlerManager interface {
	Add(protocol.ConnectionID, packetHandler)
	SetServer(unknownPacketHandler)
	Remove(protocol.ConnectionID)
	CloseServer()
}

type quicSession interface {
	Session
	handlePacket(*receivedPacket)
	GetVersion() protocol.VersionNumber
	run() error
	destroy(error)
	closeRemote(error)
}

type sessionRunner interface {
	onHandshakeComplete(Session)
	removeConnectionID(protocol.ConnectionID)
}

type runner struct {
	onHandshakeCompleteImpl func(Session)
	removeConnectionIDImpl  func(protocol.ConnectionID)
}

func (r *runner) onHandshakeComplete(s Session)              { r.onHandshakeCompleteImpl(s) }
func (r *runner) removeConnectionID(c protocol.ConnectionID) { r.removeConnectionIDImpl(c) }

var _ sessionRunner = &runner{}

// A Listener of QUIC
type server struct {
	mutex sync.Mutex

	tlsConf *tls.Config
	config  *Config

	conn net.PacketConn
	// If the server is started with ListenAddr, we create a packet conn.
	// If it is started with Listen, we take a packet conn as a parameter.
	createdPacketConn bool

	supportsTLS bool
	serverTLS   *serverTLS

	certChain crypto.CertChain
	scfg      *handshake.ServerConfig

	sessionHandler packetHandlerManager

	serverError error
	errorChan   chan struct{}
	closed      bool

	sessionQueue chan Session

	sessionRunner sessionRunner
	// set as a member, so they can be set in the tests
	newSession func(connection, sessionRunner, protocol.VersionNumber, protocol.ConnectionID, protocol.ConnectionID, *handshake.ServerConfig, *tls.Config, *Config, utils.Logger) (quicSession, error)

	logger utils.Logger
}

var _ Listener = &server{}
var _ unknownPacketHandler = &server{}

// ListenAddr creates a QUIC server listening on a given address.
// The tls.Config must not be nil, the quic.Config may be nil.
func ListenAddr(addr string, tlsConf *tls.Config, config *Config) (Listener, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	serv, err := listen(conn, tlsConf, config)
	if err != nil {
		return nil, err
	}
	serv.createdPacketConn = true
	return serv, nil
}

// Listen listens for QUIC connections on a given net.PacketConn.
// The tls.Config must not be nil, the quic.Config may be nil.
func Listen(conn net.PacketConn, tlsConf *tls.Config, config *Config) (Listener, error) {
	return listen(conn, tlsConf, config)
}

func listen(conn net.PacketConn, tlsConf *tls.Config, config *Config) (*server, error) {
	certChain := crypto.NewCertChain(tlsConf)
	kex, err := crypto.NewCurve25519KEX()
	if err != nil {
		return nil, err
	}
	scfg, err := handshake.NewServerConfig(kex, certChain)
	if err != nil {
		return nil, err
	}
	config = populateServerConfig(config)

	var supportsTLS bool
	for _, v := range config.Versions {
		if !protocol.IsValidVersion(v) {
			return nil, fmt.Errorf("%s is not a valid QUIC version", v)
		}
		// check if any of the supported versions supports TLS
		if v.UsesTLS() {
			supportsTLS = true
			break
		}
	}

	sessionHandler, err := getMultiplexer().AddConn(conn, config.ConnectionIDLength)
	if err != nil {
		return nil, err
	}
	s := &server{
		conn:           conn,
		tlsConf:        tlsConf,
		config:         config,
		certChain:      certChain,
		scfg:           scfg,
		newSession:     newSession,
		sessionHandler: sessionHandler,
		sessionQueue:   make(chan Session, 5),
		errorChan:      make(chan struct{}),
		supportsTLS:    supportsTLS,
		logger:         utils.DefaultLogger.WithPrefix("server"),
	}
	s.setup()
	if supportsTLS {
		if err := s.setupTLS(); err != nil {
			return nil, err
		}
	}
	sessionHandler.SetServer(s)
	s.logger.Debugf("Listening for %s connections on %s", conn.LocalAddr().Network(), conn.LocalAddr().String())
	return s, nil
}

func (s *server) setup() {
	s.sessionRunner = &runner{
		onHandshakeCompleteImpl: func(sess Session) { s.sessionQueue <- sess },
		removeConnectionIDImpl:  s.sessionHandler.Remove,
	}
}

func (s *server) setupTLS() error {
	serverTLS, sessionChan, err := newServerTLS(s.conn, s.config, s.sessionRunner, s.tlsConf, s.logger)
	if err != nil {
		return err
	}
	s.serverTLS = serverTLS
	// handle TLS connection establishment statelessly
	go func() {
		for {
			select {
			case <-s.errorChan:
				return
			case tlsSession := <-sessionChan:
				// The connection ID is a randomly chosen value.
				// It is safe to assume that it doesn't collide with other randomly chosen values.
				serverSession := newServerSession(tlsSession.sess, s.config, s.logger)
				s.sessionHandler.Add(tlsSession.connID, serverSession)
			}
		}
	}()
	return nil
}

var defaultAcceptCookie = func(clientAddr net.Addr, cookie *Cookie) bool {
	if cookie == nil {
		return false
	}
	if time.Now().After(cookie.SentTime.Add(protocol.CookieExpiryTime)) {
		return false
	}
	var sourceAddr string
	if udpAddr, ok := clientAddr.(*net.UDPAddr); ok {
		sourceAddr = udpAddr.IP.String()
	} else {
		sourceAddr = clientAddr.String()
	}
	return sourceAddr == cookie.RemoteAddr
}

// populateServerConfig populates fields in the quic.Config with their default values, if none are set
// it may be called with nil
func populateServerConfig(config *Config) *Config {
	if config == nil {
		config = &Config{}
	}
	versions := config.Versions
	if len(versions) == 0 {
		versions = protocol.SupportedVersions
	}

	vsa := defaultAcceptCookie
	if config.AcceptCookie != nil {
		vsa = config.AcceptCookie
	}

	handshakeTimeout := protocol.DefaultHandshakeTimeout
	if config.HandshakeTimeout != 0 {
		handshakeTimeout = config.HandshakeTimeout
	}
	idleTimeout := protocol.DefaultIdleTimeout
	if config.IdleTimeout != 0 {
		idleTimeout = config.IdleTimeout
	}

	maxReceiveStreamFlowControlWindow := config.MaxReceiveStreamFlowControlWindow
	if maxReceiveStreamFlowControlWindow == 0 {
		maxReceiveStreamFlowControlWindow = protocol.DefaultMaxReceiveStreamFlowControlWindowServer
	}
	maxReceiveConnectionFlowControlWindow := config.MaxReceiveConnectionFlowControlWindow
	if maxReceiveConnectionFlowControlWindow == 0 {
		maxReceiveConnectionFlowControlWindow = protocol.DefaultMaxReceiveConnectionFlowControlWindowServer
	}
	maxIncomingStreams := config.MaxIncomingStreams
	if maxIncomingStreams == 0 {
		maxIncomingStreams = protocol.DefaultMaxIncomingStreams
	} else if maxIncomingStreams < 0 {
		maxIncomingStreams = 0
	}
	maxIncomingUniStreams := config.MaxIncomingUniStreams
	if maxIncomingUniStreams == 0 {
		maxIncomingUniStreams = protocol.DefaultMaxIncomingUniStreams
	} else if maxIncomingUniStreams < 0 {
		maxIncomingUniStreams = 0
	}
	connIDLen := config.ConnectionIDLength
	if connIDLen == 0 {
		connIDLen = protocol.DefaultConnectionIDLength
	}
	for _, v := range versions {
		if v == protocol.Version44 {
			connIDLen = protocol.ConnectionIDLenGQUIC
		}
	}

	return &Config{
		Versions:                              versions,
		HandshakeTimeout:                      handshakeTimeout,
		IdleTimeout:                           idleTimeout,
		AcceptCookie:                          vsa,
		KeepAlive:                             config.KeepAlive,
		MaxReceiveStreamFlowControlWindow:     maxReceiveStreamFlowControlWindow,
		MaxReceiveConnectionFlowControlWindow: maxReceiveConnectionFlowControlWindow,
		MaxIncomingStreams:                    maxIncomingStreams,
		MaxIncomingUniStreams:                 maxIncomingUniStreams,
		ConnectionIDLength:                    connIDLen,
	}
}

// Accept returns newly openend sessions
func (s *server) Accept() (Session, error) {
	var sess Session
	select {
	case sess = <-s.sessionQueue:
		return sess, nil
	case <-s.errorChan:
		return nil, s.serverError
	}
}

// Close the server
func (s *server) Close() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.closed {
		return nil
	}
	return s.closeWithMutex()
}

func (s *server) closeWithMutex() error {
	s.sessionHandler.CloseServer()
	if s.serverError == nil {
		s.serverError = errors.New("server closed")
	}
	var err error
	// If the server was started with ListenAddr, we created the packet conn.
	// We need to close it in order to make the go routine reading from that conn return.
	if s.createdPacketConn {
		err = s.conn.Close()
	}
	s.closed = true
	close(s.errorChan)
	return err
}

func (s *server) closeWithError(e error) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.closed {
		return nil
	}
	s.serverError = e
	return s.closeWithMutex()
}

// Addr returns the server's network address
func (s *server) Addr() net.Addr {
	return s.conn.LocalAddr()
}

func (s *server) handlePacket(p *receivedPacket) {
	if err := s.handlePacketImpl(p); err != nil {
		s.logger.Debugf("error handling packet from %s: %s", p.remoteAddr, err)
	}
}

func (s *server) handlePacketImpl(p *receivedPacket) error {
	hdr := p.header

	if hdr.VersionFlag || hdr.IsLongHeader {
		// send a Version Negotiation Packet if the client is speaking a different protocol version
		if !protocol.IsSupportedVersion(s.config.Versions, hdr.Version) {
			return s.sendVersionNegotiationPacket(p)
		}
	}
	if hdr.Type == protocol.PacketTypeInitial && hdr.Version.UsesTLS() {
		go s.serverTLS.HandleInitial(p)
		return nil
	}

	// TODO(#943): send Stateless Reset, if this an IETF QUIC packet
	if !hdr.VersionFlag && !hdr.Version.UsesIETFHeaderFormat() {
		_, err := s.conn.WriteTo(wire.WritePublicReset(hdr.DestConnectionID, 0, 0), p.remoteAddr)
		return err
	}

	// This is (potentially) a Client Hello.
	// Make sure it has the minimum required size before spending any more ressources on it.
	if len(p.data) < protocol.MinClientHelloSize {
		return errors.New("dropping small packet for unknown connection")
	}

	var destConnID, srcConnID protocol.ConnectionID
	if hdr.Version.UsesIETFHeaderFormat() {
		srcConnID = hdr.DestConnectionID
	} else {
		destConnID = hdr.DestConnectionID
		srcConnID = hdr.DestConnectionID
	}
	s.logger.Infof("Serving new connection: %s, version %s from %v", hdr.DestConnectionID, hdr.Version, p.remoteAddr)
	sess, err := s.newSession(
		&conn{pconn: s.conn, currentAddr: p.remoteAddr},
		s.sessionRunner,
		hdr.Version,
		destConnID,
		srcConnID,
		s.scfg,
		s.tlsConf,
		s.config,
		s.logger,
	)
	if err != nil {
		return err
	}
	s.sessionHandler.Add(hdr.DestConnectionID, newServerSession(sess, s.config, s.logger))
	go sess.run()
	sess.handlePacket(p)
	return nil
}

func (s *server) sendVersionNegotiationPacket(p *receivedPacket) error {
	hdr := p.header
	s.logger.Debugf("Client offered version %s, sending VersionNegotiationPacket", hdr.Version)

	var data []byte
	if hdr.IsPublicHeader {
		data = wire.ComposeGQUICVersionNegotiation(hdr.DestConnectionID, s.config.Versions)
	} else {
		var err error
		data, err = wire.ComposeVersionNegotiation(hdr.SrcConnectionID, hdr.DestConnectionID, s.config.Versions)
		if err != nil {
			return err
		}
	}
	_, err := s.conn.WriteTo(data, p.remoteAddr)
	return err
}
