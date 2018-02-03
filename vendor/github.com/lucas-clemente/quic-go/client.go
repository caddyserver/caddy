package quic

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"github.com/lucas-clemente/quic-go/qerr"
)

type client struct {
	mutex sync.Mutex

	conn     connection
	hostname string

	versionNegotiationChan           chan struct{} // the versionNegotiationChan is closed as soon as the server accepted the suggested version
	versionNegotiated                bool          // has the server accepted our version
	receivedVersionNegotiationPacket bool
	negotiatedVersions               []protocol.VersionNumber // the list of versions from the version negotiation packet

	tlsConf *tls.Config
	config  *Config
	tls     handshake.MintTLS // only used when using TLS

	connectionID protocol.ConnectionID

	initialVersion protocol.VersionNumber
	version        protocol.VersionNumber

	session packetHandler
}

var (
	// make it possible to mock connection ID generation in the tests
	generateConnectionID         = utils.GenerateConnectionID
	errCloseSessionForNewVersion = errors.New("closing session in order to recreate it with a new version")
)

// DialAddr establishes a new QUIC connection to a server.
// The hostname for SNI is taken from the given address.
func DialAddr(addr string, tlsConf *tls.Config, config *Config) (Session, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}
	return Dial(udpConn, udpAddr, addr, tlsConf, config)
}

// Dial establishes a new QUIC connection to a server using a net.PacketConn.
// The host parameter is used for SNI.
func Dial(
	pconn net.PacketConn,
	remoteAddr net.Addr,
	host string,
	tlsConf *tls.Config,
	config *Config,
) (Session, error) {
	connID, err := generateConnectionID()
	if err != nil {
		return nil, err
	}

	var hostname string
	if tlsConf != nil {
		hostname = tlsConf.ServerName
	}
	if hostname == "" {
		hostname, _, err = net.SplitHostPort(host)
		if err != nil {
			return nil, err
		}
	}

	clientConfig := populateClientConfig(config)
	c := &client{
		conn:                   &conn{pconn: pconn, currentAddr: remoteAddr},
		connectionID:           connID,
		hostname:               hostname,
		tlsConf:                tlsConf,
		config:                 clientConfig,
		version:                clientConfig.Versions[0],
		versionNegotiationChan: make(chan struct{}),
	}

	utils.Infof("Starting new connection to %s (%s -> %s), connectionID %x, version %s", hostname, c.conn.LocalAddr().String(), c.conn.RemoteAddr().String(), c.connectionID, c.version)

	if err := c.dial(); err != nil {
		return nil, err
	}
	return c.session, nil
}

// populateClientConfig populates fields in the quic.Config with their default values, if none are set
// it may be called with nil
func populateClientConfig(config *Config) *Config {
	if config == nil {
		config = &Config{}
	}
	versions := config.Versions
	if len(versions) == 0 {
		versions = protocol.SupportedVersions
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
		maxReceiveStreamFlowControlWindow = protocol.DefaultMaxReceiveStreamFlowControlWindowClient
	}
	maxReceiveConnectionFlowControlWindow := config.MaxReceiveConnectionFlowControlWindow
	if maxReceiveConnectionFlowControlWindow == 0 {
		maxReceiveConnectionFlowControlWindow = protocol.DefaultMaxReceiveConnectionFlowControlWindowClient
	}

	return &Config{
		Versions:                              versions,
		HandshakeTimeout:                      handshakeTimeout,
		IdleTimeout:                           idleTimeout,
		RequestConnectionIDOmission:           config.RequestConnectionIDOmission,
		MaxReceiveStreamFlowControlWindow:     maxReceiveStreamFlowControlWindow,
		MaxReceiveConnectionFlowControlWindow: maxReceiveConnectionFlowControlWindow,
		KeepAlive: config.KeepAlive,
	}
}

func (c *client) dial() error {
	var err error
	if c.version.UsesTLS() {
		err = c.dialTLS()
	} else {
		err = c.dialGQUIC()
	}
	if err == errCloseSessionForNewVersion {
		return c.dial()
	}
	return err
}

func (c *client) dialGQUIC() error {
	if err := c.createNewGQUICSession(); err != nil {
		return err
	}
	go c.listen()
	return c.establishSecureConnection()
}

func (c *client) dialTLS() error {
	params := &handshake.TransportParameters{
		StreamFlowControlWindow:     protocol.ReceiveStreamFlowControlWindow,
		ConnectionFlowControlWindow: protocol.ReceiveConnectionFlowControlWindow,
		MaxStreams:                  protocol.MaxIncomingStreams,
		IdleTimeout:                 c.config.IdleTimeout,
		OmitConnectionID:            c.config.RequestConnectionIDOmission,
	}
	csc := handshake.NewCryptoStreamConn(nil)
	extHandler := handshake.NewExtensionHandlerClient(params, c.initialVersion, c.config.Versions, c.version)
	mintConf, err := tlsToMintConfig(c.tlsConf, protocol.PerspectiveClient)
	if err != nil {
		return err
	}
	mintConf.ExtensionHandler = extHandler
	mintConf.ServerName = c.hostname
	c.tls = newMintController(csc, mintConf, protocol.PerspectiveClient)

	if err := c.createNewTLSSession(extHandler.GetPeerParams(), c.version); err != nil {
		return err
	}
	go c.listen()
	if err := c.establishSecureConnection(); err != nil {
		if err != handshake.ErrCloseSessionForRetry {
			return err
		}
		utils.Infof("Received a Retry packet. Recreating session.")
		if err := c.createNewTLSSession(extHandler.GetPeerParams(), c.version); err != nil {
			return err
		}
		if err := c.establishSecureConnection(); err != nil {
			return err
		}
	}
	return nil
}

// establishSecureConnection runs the session, and tries to establish a secure connection
// It returns:
// - errCloseSessionForNewVersion when the server sends a version negotiation packet
// - handshake.ErrCloseSessionForRetry when the server performs a stateless retry (for IETF QUIC)
// - any other error that might occur
// - when the connection is secure (for gQUIC), or forward-secure (for IETF QUIC)
func (c *client) establishSecureConnection() error {
	var runErr error
	errorChan := make(chan struct{})
	go func() {
		runErr = c.session.run() // returns as soon as the session is closed
		close(errorChan)
		utils.Infof("Connection %x closed.", c.connectionID)
		if runErr != handshake.ErrCloseSessionForRetry && runErr != errCloseSessionForNewVersion {
			c.conn.Close()
		}
	}()

	// wait until the server accepts the QUIC version (or an error occurs)
	select {
	case <-errorChan:
		return runErr
	case <-c.versionNegotiationChan:
	}

	select {
	case <-errorChan:
		return runErr
	case err := <-c.session.handshakeStatus():
		return err
	}
}

// Listen listens on the underlying connection and passes packets on for handling.
// It returns when the connection is closed.
func (c *client) listen() {
	var err error

	for {
		var n int
		var addr net.Addr
		data := getPacketBuffer()
		data = data[:protocol.MaxReceivePacketSize]
		// The packet size should not exceed protocol.MaxReceivePacketSize bytes
		// If it does, we only read a truncated packet, which will then end up undecryptable
		n, addr, err = c.conn.Read(data)
		if err != nil {
			if !strings.HasSuffix(err.Error(), "use of closed network connection") {
				c.mutex.Lock()
				if c.session != nil {
					c.session.Close(err)
				}
				c.mutex.Unlock()
			}
			break
		}
		c.handlePacket(addr, data[:n])
	}
}

func (c *client) handlePacket(remoteAddr net.Addr, packet []byte) {
	rcvTime := time.Now()

	r := bytes.NewReader(packet)
	hdr, err := wire.ParseHeaderSentByServer(r, c.version)
	if err != nil {
		utils.Errorf("error parsing packet from %s: %s", remoteAddr.String(), err.Error())
		// drop this packet if we can't parse the header
		return
	}
	// reject packets with truncated connection id if we didn't request truncation
	if hdr.OmitConnectionID && !c.config.RequestConnectionIDOmission {
		return
	}
	hdr.Raw = packet[:len(packet)-r.Len()]

	c.mutex.Lock()
	defer c.mutex.Unlock()

	// reject packets with the wrong connection ID
	if !hdr.OmitConnectionID && hdr.ConnectionID != c.connectionID {
		return
	}

	if hdr.ResetFlag {
		cr := c.conn.RemoteAddr()
		// check if the remote address and the connection ID match
		// otherwise this might be an attacker trying to inject a PUBLIC_RESET to kill the connection
		if cr.Network() != remoteAddr.Network() || cr.String() != remoteAddr.String() || hdr.ConnectionID != c.connectionID {
			utils.Infof("Received a spoofed Public Reset. Ignoring.")
			return
		}
		pr, err := wire.ParsePublicReset(r)
		if err != nil {
			utils.Infof("Received a Public Reset. An error occurred parsing the packet: %s", err)
			return
		}
		utils.Infof("Received Public Reset, rejected packet number: %#x.", pr.RejectedPacketNumber)
		c.session.closeRemote(qerr.Error(qerr.PublicReset, fmt.Sprintf("Received a Public Reset for packet number %#x", pr.RejectedPacketNumber)))
		return
	}

	// handle Version Negotiation Packets
	if hdr.IsVersionNegotiation {
		// ignore delayed / duplicated version negotiation packets
		if c.receivedVersionNegotiationPacket || c.versionNegotiated {
			return
		}

		// version negotiation packets have no payload
		if err := c.handleVersionNegotiationPacket(hdr); err != nil {
			c.session.Close(err)
		}
		return
	}

	// this is the first packet we are receiving
	// since it is not a Version Negotiation Packet, this means the server supports the suggested version
	if !c.versionNegotiated {
		c.versionNegotiated = true
		close(c.versionNegotiationChan)
	}

	// TODO: validate packet number and connection ID on Retry packets (for IETF QUIC)

	c.session.handlePacket(&receivedPacket{
		remoteAddr: remoteAddr,
		header:     hdr,
		data:       packet[len(packet)-r.Len():],
		rcvTime:    rcvTime,
	})
}

func (c *client) handleVersionNegotiationPacket(hdr *wire.Header) error {
	for _, v := range hdr.SupportedVersions {
		if v == c.version {
			// the version negotiation packet contains the version that we offered
			// this might be a packet sent by an attacker (or by a terribly broken server implementation)
			// ignore it
			return nil
		}
	}

	newVersion, ok := protocol.ChooseSupportedVersion(c.config.Versions, hdr.SupportedVersions)
	if !ok {
		return qerr.InvalidVersion
	}
	c.receivedVersionNegotiationPacket = true
	c.negotiatedVersions = hdr.SupportedVersions

	// switch to negotiated version
	c.initialVersion = c.version
	c.version = newVersion
	var err error
	c.connectionID, err = utils.GenerateConnectionID()
	if err != nil {
		return err
	}
	utils.Infof("Switching to QUIC version %s. New connection ID: %x", newVersion, c.connectionID)
	c.session.Close(errCloseSessionForNewVersion)
	return nil
}

func (c *client) createNewGQUICSession() (err error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.session, err = newClientSession(
		c.conn,
		c.hostname,
		c.version,
		c.connectionID,
		c.tlsConf,
		c.config,
		c.initialVersion,
		c.negotiatedVersions,
	)
	return err
}

func (c *client) createNewTLSSession(
	paramsChan <-chan handshake.TransportParameters,
	version protocol.VersionNumber,
) (err error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.session, err = newTLSClientSession(
		c.conn,
		c.hostname,
		c.version,
		c.connectionID,
		c.config,
		c.tls,
		paramsChan,
		1,
	)
	return err
}
