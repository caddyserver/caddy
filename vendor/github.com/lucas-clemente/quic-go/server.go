package quic

import (
	"bytes"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/internal/crypto"
	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"github.com/lucas-clemente/quic-go/qerr"
)

// packetHandler handles packets
type packetHandler interface {
	Session
	getCryptoStream() cryptoStreamI
	handshakeStatus() <-chan error
	handlePacket(*receivedPacket)
	GetVersion() protocol.VersionNumber
	run() error
	closeRemote(error)
}

// A Listener of QUIC
type server struct {
	tlsConf *tls.Config
	config  *Config

	conn net.PacketConn

	supportsTLS bool
	serverTLS   *serverTLS

	certChain crypto.CertChain
	scfg      *handshake.ServerConfig

	sessionsMutex sync.RWMutex
	sessions      map[protocol.ConnectionID]packetHandler
	closed        bool

	serverError  error
	sessionQueue chan Session
	errorChan    chan struct{}

	// set as members, so they can be set in the tests
	newSession                func(conn connection, v protocol.VersionNumber, connectionID protocol.ConnectionID, sCfg *handshake.ServerConfig, tlsConf *tls.Config, config *Config) (packetHandler, error)
	deleteClosedSessionsAfter time.Duration
}

var _ Listener = &server{}

// ListenAddr creates a QUIC server listening on a given address.
// The listener is not active until Serve() is called.
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
	return Listen(conn, tlsConf, config)
}

// Listen listens for QUIC connections on a given net.PacketConn.
// The listener is not active until Serve() is called.
// The tls.Config must not be nil, the quic.Config may be nil.
func Listen(conn net.PacketConn, tlsConf *tls.Config, config *Config) (Listener, error) {
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

	// check if any of the supported versions supports TLS
	var supportsTLS bool
	for _, v := range config.Versions {
		if v.UsesTLS() {
			supportsTLS = true
			break
		}
	}

	s := &server{
		conn:                      conn,
		tlsConf:                   tlsConf,
		config:                    config,
		certChain:                 certChain,
		scfg:                      scfg,
		sessions:                  map[protocol.ConnectionID]packetHandler{},
		newSession:                newSession,
		deleteClosedSessionsAfter: protocol.ClosedSessionDeleteTimeout,
		sessionQueue:              make(chan Session, 5),
		errorChan:                 make(chan struct{}),
		supportsTLS:               supportsTLS,
	}
	if supportsTLS {
		if err := s.setupTLS(); err != nil {
			return nil, err
		}
	}
	go s.serve()
	utils.Debugf("Listening for %s connections on %s", conn.LocalAddr().Network(), conn.LocalAddr().String())
	return s, nil
}

func (s *server) setupTLS() error {
	cookieHandler, err := handshake.NewCookieHandler(s.config.AcceptCookie)
	if err != nil {
		return err
	}
	serverTLS, sessionChan, err := newServerTLS(s.conn, s.config, cookieHandler, s.tlsConf)
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
			case sess := <-sessionChan:
				// TODO: think about what to do with connection ID collisions
				connID := sess.(*session).connectionID
				s.sessionsMutex.Lock()
				s.sessions[connID] = sess
				s.sessionsMutex.Unlock()
				s.runHandshakeAndSession(sess, connID)
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

	return &Config{
		Versions:                              versions,
		HandshakeTimeout:                      handshakeTimeout,
		IdleTimeout:                           idleTimeout,
		AcceptCookie:                          vsa,
		KeepAlive:                             config.KeepAlive,
		MaxReceiveStreamFlowControlWindow:     maxReceiveStreamFlowControlWindow,
		MaxReceiveConnectionFlowControlWindow: maxReceiveConnectionFlowControlWindow,
	}
}

// serve listens on an existing PacketConn
func (s *server) serve() {
	for {
		data := getPacketBuffer()
		data = data[:protocol.MaxReceivePacketSize]
		// The packet size should not exceed protocol.MaxReceivePacketSize bytes
		// If it does, we only read a truncated packet, which will then end up undecryptable
		n, remoteAddr, err := s.conn.ReadFrom(data)
		if err != nil {
			s.serverError = err
			close(s.errorChan)
			_ = s.Close()
			return
		}
		data = data[:n]
		if err := s.handlePacket(s.conn, remoteAddr, data); err != nil {
			utils.Errorf("error handling packet: %s", err.Error())
		}
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
	s.sessionsMutex.Lock()
	if s.closed {
		s.sessionsMutex.Unlock()
		return nil
	}
	s.closed = true

	var wg sync.WaitGroup
	for _, session := range s.sessions {
		if session != nil {
			wg.Add(1)
			go func(sess packetHandler) {
				// session.Close() blocks until the CONNECTION_CLOSE has been sent and the run-loop has stopped
				_ = sess.Close(nil)
				wg.Done()
			}(session)
		}
	}
	s.sessionsMutex.Unlock()
	wg.Wait()

	err := s.conn.Close()
	<-s.errorChan // wait for serve() to return
	return err
}

// Addr returns the server's network address
func (s *server) Addr() net.Addr {
	return s.conn.LocalAddr()
}

func (s *server) handlePacket(pconn net.PacketConn, remoteAddr net.Addr, packet []byte) error {
	rcvTime := time.Now()

	r := bytes.NewReader(packet)
	hdr, err := wire.ParseHeaderSentByClient(r)
	if err != nil {
		return qerr.Error(qerr.InvalidPacketHeader, err.Error())
	}
	hdr.Raw = packet[:len(packet)-r.Len()]
	packetData := packet[len(packet)-r.Len():]
	connID := hdr.ConnectionID

	if hdr.Type == protocol.PacketTypeInitial {
		if s.supportsTLS {
			go s.serverTLS.HandleInitial(remoteAddr, hdr, packetData)
		}
		return nil
	}

	s.sessionsMutex.RLock()
	session, sessionKnown := s.sessions[connID]
	s.sessionsMutex.RUnlock()

	if sessionKnown && session == nil {
		// Late packet for closed session
		return nil
	}

	// ignore all Public Reset packets
	if hdr.ResetFlag {
		if sessionKnown {
			var pr *wire.PublicReset
			pr, err = wire.ParsePublicReset(r)
			if err != nil {
				utils.Infof("Received a Public Reset for connection %x. An error occurred parsing the packet.")
			} else {
				utils.Infof("Received a Public Reset for connection %x, rejected packet number: 0x%x.", hdr.ConnectionID, pr.RejectedPacketNumber)
			}
		} else {
			utils.Infof("Received Public Reset for unknown connection %x.", hdr.ConnectionID)
		}
		return nil
	}

	// If we don't have a session for this connection, and this packet cannot open a new connection, send a Public Reset
	// This should only happen after a server restart, when we still receive packets for connections that we lost the state for.
	// TODO(#943): implement sending of IETF draft style stateless resets
	if !sessionKnown && (!hdr.VersionFlag && hdr.Type != protocol.PacketTypeInitial) {
		_, err = pconn.WriteTo(wire.WritePublicReset(connID, 0, 0), remoteAddr)
		return err
	}

	// a session is only created once the client sent a supported version
	// if we receive a packet for a connection that already has session, it's probably an old packet that was sent by the client before the version was negotiated
	// it is safe to drop it
	if sessionKnown && hdr.VersionFlag && !protocol.IsSupportedVersion(s.config.Versions, hdr.Version) {
		return nil
	}

	// send a Version Negotiation Packet if the client is speaking a different protocol version
	// since the client send a Public Header (only gQUIC has a Version Flag), we need to send a gQUIC Version Negotiation Packet
	if hdr.VersionFlag && !protocol.IsSupportedVersion(s.config.Versions, hdr.Version) {
		// drop packets that are too small to be valid first packets
		if len(packet) < protocol.MinClientHelloSize+len(hdr.Raw) {
			return errors.New("dropping small packet with unknown version")
		}
		utils.Infof("Client offered version %s, sending Version Negotiation Packet", hdr.Version)
		_, err := pconn.WriteTo(wire.ComposeGQUICVersionNegotiation(hdr.ConnectionID, s.config.Versions), remoteAddr)
		return err
	}

	// This is (potentially) a Client Hello.
	// Make sure it has the minimum required size before spending any more ressources on it.
	if !sessionKnown && len(packet) < protocol.MinClientHelloSize+len(hdr.Raw) {
		return errors.New("dropping small packet for unknown connection")
	}

	if !sessionKnown {
		version := hdr.Version
		if !protocol.IsSupportedVersion(s.config.Versions, version) {
			return errors.New("Server BUG: negotiated version not supported")
		}

		utils.Infof("Serving new connection: %x, version %s from %v", hdr.ConnectionID, version, remoteAddr)
		session, err = s.newSession(
			&conn{pconn: pconn, currentAddr: remoteAddr},
			version,
			hdr.ConnectionID,
			s.scfg,
			s.tlsConf,
			s.config,
		)
		if err != nil {
			return err
		}
		s.sessionsMutex.Lock()
		s.sessions[connID] = session
		s.sessionsMutex.Unlock()

		s.runHandshakeAndSession(session, connID)
	}
	session.handlePacket(&receivedPacket{
		remoteAddr: remoteAddr,
		header:     hdr,
		data:       packetData,
		rcvTime:    rcvTime,
	})
	return nil
}

func (s *server) runHandshakeAndSession(session packetHandler, connID protocol.ConnectionID) {
	go func() {
		_ = session.run()
		// session.run() returns as soon as the session is closed
		s.removeConnection(connID)
	}()

	go func() {
		if err := <-session.handshakeStatus(); err != nil {
			return
		}
		s.sessionQueue <- session
	}()
}

func (s *server) removeConnection(id protocol.ConnectionID) {
	s.sessionsMutex.Lock()
	s.sessions[id] = nil
	s.sessionsMutex.Unlock()

	time.AfterFunc(s.deleteClosedSessionsAfter, func() {
		s.sessionsMutex.Lock()
		delete(s.sessions, id)
		s.sessionsMutex.Unlock()
	})
}
