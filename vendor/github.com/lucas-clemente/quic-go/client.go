package quic

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	"github.com/lucas-clemente/quic-go/utils"
)

type client struct {
	mutex     sync.Mutex
	listenErr error

	conn     connection
	hostname string

	errorChan     chan struct{}
	handshakeChan <-chan handshakeEvent

	config            *Config
	versionNegotiated bool // has version negotiation completed yet

	connectionID protocol.ConnectionID
	version      protocol.VersionNumber

	session packetHandler
}

var (
	errCloseSessionForNewVersion = errors.New("closing session in order to recreate it with a new version")
)

// DialAddr establishes a new QUIC connection to a server.
// The hostname for SNI is taken from the given address.
func DialAddr(addr string, config *Config) (Session, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}
	return Dial(udpConn, udpAddr, addr, config)
}

// DialAddrNonFWSecure establishes a new QUIC connection to a server.
// The hostname for SNI is taken from the given address.
func DialAddrNonFWSecure(addr string, config *Config) (NonFWSession, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}
	return DialNonFWSecure(udpConn, udpAddr, addr, config)
}

// DialNonFWSecure establishes a new non-forward-secure QUIC connection to a server using a net.PacketConn.
// The host parameter is used for SNI.
func DialNonFWSecure(pconn net.PacketConn, remoteAddr net.Addr, host string, config *Config) (NonFWSession, error) {
	connID, err := utils.GenerateConnectionID()
	if err != nil {
		return nil, err
	}

	hostname, _, err := net.SplitHostPort(host)
	if err != nil {
		return nil, err
	}

	clientConfig := populateClientConfig(config)
	c := &client{
		conn:         &conn{pconn: pconn, currentAddr: remoteAddr},
		connectionID: connID,
		hostname:     hostname,
		config:       clientConfig,
		version:      clientConfig.Versions[0],
		errorChan:    make(chan struct{}),
	}

	err = c.createNewSession(nil)
	if err != nil {
		return nil, err
	}

	utils.Infof("Starting new connection to %s (%s), connectionID %x, version %d", hostname, c.conn.RemoteAddr().String(), c.connectionID, c.version)

	return c.session.(NonFWSession), c.establishSecureConnection()
}

// Dial establishes a new QUIC connection to a server using a net.PacketConn.
// The host parameter is used for SNI.
func Dial(pconn net.PacketConn, remoteAddr net.Addr, host string, config *Config) (Session, error) {
	sess, err := DialNonFWSecure(pconn, remoteAddr, host, config)
	if err != nil {
		return nil, err
	}
	err = sess.WaitUntilHandshakeComplete()
	if err != nil {
		return nil, err
	}
	return sess, nil
}

func populateClientConfig(config *Config) *Config {
	versions := config.Versions
	if len(versions) == 0 {
		versions = protocol.SupportedVersions
	}

	return &Config{
		TLSConfig:                     config.TLSConfig,
		Versions:                      versions,
		RequestConnectionIDTruncation: config.RequestConnectionIDTruncation,
	}
}

// establishSecureConnection returns as soon as the connection is secure (as opposed to forward-secure)
func (c *client) establishSecureConnection() error {
	go c.listen()

	select {
	case <-c.errorChan:
		return c.listenErr
	case ev := <-c.handshakeChan:
		if ev.err != nil {
			return ev.err
		}
		if ev.encLevel != protocol.EncryptionSecure {
			return fmt.Errorf("Client BUG: Expected encryption level to be secure, was %s", ev.encLevel)
		}
		return nil
	}
}

// Listen listens
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
				c.session.Close(err)
			}
			break
		}
		data = data[:n]

		err = c.handlePacket(addr, data)
		if err != nil {
			utils.Errorf("error handling packet: %s", err.Error())
			c.session.Close(err)
			break
		}
	}
}

func (c *client) handlePacket(remoteAddr net.Addr, packet []byte) error {
	rcvTime := time.Now()

	r := bytes.NewReader(packet)
	hdr, err := ParsePublicHeader(r, protocol.PerspectiveServer)
	if err != nil {
		return qerr.Error(qerr.InvalidPacketHeader, err.Error())
	}
	hdr.Raw = packet[:len(packet)-r.Len()]

	c.mutex.Lock()
	defer c.mutex.Unlock()

	// ignore delayed / duplicated version negotiation packets
	if c.versionNegotiated && hdr.VersionFlag {
		return nil
	}

	// this is the first packet after the client sent a packet with the VersionFlag set
	// if the server doesn't send a version negotiation packet, it supports the suggested version
	if !hdr.VersionFlag && !c.versionNegotiated {
		c.versionNegotiated = true
	}

	if hdr.VersionFlag {
		// version negotiation packets have no payload
		return c.handlePacketWithVersionFlag(hdr)
	}

	c.session.handlePacket(&receivedPacket{
		remoteAddr:   remoteAddr,
		publicHeader: hdr,
		data:         packet[len(packet)-r.Len():],
		rcvTime:      rcvTime,
	})
	return nil
}

func (c *client) handlePacketWithVersionFlag(hdr *PublicHeader) error {
	for _, v := range hdr.SupportedVersions {
		if v == c.version {
			// the version negotiation packet contains the version that we offered
			// this might be a packet sent by an attacker (or by a terribly broken server implementation)
			// ignore it
			return nil
		}
	}

	newVersion := protocol.ChooseSupportedVersion(c.config.Versions, hdr.SupportedVersions)
	if newVersion == protocol.VersionUnsupported {
		return qerr.InvalidVersion
	}

	// switch to negotiated version
	c.version = newVersion
	c.versionNegotiated = true
	var err error
	c.connectionID, err = utils.GenerateConnectionID()
	if err != nil {
		return err
	}
	utils.Infof("Switching to QUIC version %d. New connection ID: %x", newVersion, c.connectionID)

	c.session.Close(errCloseSessionForNewVersion)
	return c.createNewSession(hdr.SupportedVersions)
}

func (c *client) createNewSession(negotiatedVersions []protocol.VersionNumber) error {
	var err error
	c.session, c.handshakeChan, err = newClientSession(
		c.conn,
		c.hostname,
		c.version,
		c.connectionID,
		c.config,
		negotiatedVersions,
	)
	if err != nil {
		return err
	}

	go func() {
		// session.run() returns as soon as the session is closed
		err := c.session.run()
		if err == errCloseSessionForNewVersion {
			return
		}
		c.listenErr = err
		close(c.errorChan)

		utils.Infof("Connection %x closed.", c.connectionID)
		c.conn.Close()
	}()
	return nil
}
