package quicproxy

import (
	"bytes"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/protocol"
)

// Connection is a UDP connection
type connection struct {
	ClientAddr *net.UDPAddr // Address of the client
	ServerConn *net.UDPConn // UDP connection to server

	incomingPacketCounter uint64
	outgoingPacketCounter uint64
}

// Direction is the direction a packet is sent.
type Direction int

const (
	// DirectionIncoming is the direction from the client to the server.
	DirectionIncoming Direction = iota
	// DirectionOutgoing is the direction from the server to the client.
	DirectionOutgoing
)

// DropCallback is a callback that determines which packet gets dropped.
type DropCallback func(Direction, protocol.PacketNumber) bool

// NoDropper doesn't drop packets.
var NoDropper DropCallback = func(Direction, protocol.PacketNumber) bool {
	return false
}

// DelayCallback is a callback that determines how much delay to apply to a packet.
type DelayCallback func(Direction, protocol.PacketNumber) time.Duration

// NoDelay doesn't apply a delay.
var NoDelay DelayCallback = func(Direction, protocol.PacketNumber) time.Duration {
	return 0
}

// Opts are proxy options.
type Opts struct {
	// The address this proxy proxies packets to.
	RemoteAddr string
	// DropPacket determines whether a packet gets dropped.
	DropPacket DropCallback
	// DelayPacket determines how long a packet gets delayed. This allows
	// simulating a connection with non-zero RTTs.
	// Note that the RTT is the sum of the delay for the incoming and the outgoing packet.
	DelayPacket DelayCallback
}

// QuicProxy is a QUIC proxy that can drop and delay packets.
type QuicProxy struct {
	mutex sync.Mutex

	conn       *net.UDPConn
	serverAddr *net.UDPAddr

	dropPacket  DropCallback
	delayPacket DelayCallback

	// Mapping from client addresses (as host:port) to connection
	clientDict map[string]*connection
}

// NewQuicProxy creates a new UDP proxy
func NewQuicProxy(local string, opts Opts) (*QuicProxy, error) {
	laddr, err := net.ResolveUDPAddr("udp", local)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, err
	}
	raddr, err := net.ResolveUDPAddr("udp", opts.RemoteAddr)
	if err != nil {
		return nil, err
	}

	packetDropper := NoDropper
	if opts.DropPacket != nil {
		packetDropper = opts.DropPacket
	}

	packetDelayer := NoDelay
	if opts.DelayPacket != nil {
		packetDelayer = opts.DelayPacket
	}

	p := QuicProxy{
		clientDict:  make(map[string]*connection),
		conn:        conn,
		serverAddr:  raddr,
		dropPacket:  packetDropper,
		delayPacket: packetDelayer,
	}

	go p.runProxy()
	return &p, nil
}

// Close stops the UDP Proxy
func (p *QuicProxy) Close() error {
	return p.conn.Close()
}

// LocalAddr is the address the proxy is listening on.
func (p *QuicProxy) LocalAddr() net.Addr {
	return p.conn.LocalAddr()
}

func (p *QuicProxy) LocalPort() int {
	return p.conn.LocalAddr().(*net.UDPAddr).Port
}

func (p *QuicProxy) newConnection(cliAddr *net.UDPAddr) (*connection, error) {
	srvudp, err := net.DialUDP("udp", nil, p.serverAddr)
	if err != nil {
		return nil, err
	}
	return &connection{
		ClientAddr: cliAddr,
		ServerConn: srvudp,
	}, nil
}

// runProxy listens on the proxy address and handles incoming packets.
func (p *QuicProxy) runProxy() error {
	for {
		buffer := make([]byte, protocol.MaxPacketSize)
		n, cliaddr, err := p.conn.ReadFromUDP(buffer)
		if err != nil {
			return err
		}
		raw := buffer[0:n]

		saddr := cliaddr.String()
		p.mutex.Lock()
		conn, ok := p.clientDict[saddr]

		if !ok {
			conn, err = p.newConnection(cliaddr)
			if err != nil {
				p.mutex.Unlock()
				return err
			}
			p.clientDict[saddr] = conn
			go p.runConnection(conn)
		}
		p.mutex.Unlock()

		atomic.AddUint64(&conn.incomingPacketCounter, 1)

		r := bytes.NewReader(raw)
		hdr, err := quic.ParsePublicHeader(r, protocol.PerspectiveClient)
		if err != nil {
			return err
		}

		if p.dropPacket(DirectionIncoming, hdr.PacketNumber) {
			continue
		}

		// Send the packet to the server
		delay := p.delayPacket(DirectionIncoming, hdr.PacketNumber)
		if delay != 0 {
			time.AfterFunc(delay, func() {
				// TODO: handle error
				_, _ = conn.ServerConn.Write(raw)
			})
		} else {
			_, err := conn.ServerConn.Write(raw)
			if err != nil {
				return err
			}
		}
	}
}

// runConnection handles packets from server to a single client
func (p *QuicProxy) runConnection(conn *connection) error {
	for {
		buffer := make([]byte, protocol.MaxPacketSize)
		n, err := conn.ServerConn.Read(buffer)
		if err != nil {
			return err
		}
		raw := buffer[0:n]

		// TODO: Switch back to using the public header once Chrome properly sets the type byte.
		// r := bytes.NewReader(raw)
		// , err := quic.ParsePublicHeader(r, protocol.PerspectiveServer)
		// if err != nil {
		// return err
		// }

		v := atomic.AddUint64(&conn.outgoingPacketCounter, 1)

		packetNumber := protocol.PacketNumber(v)
		if p.dropPacket(DirectionOutgoing, packetNumber) {
			continue
		}

		delay := p.delayPacket(DirectionOutgoing, packetNumber)
		if delay != 0 {
			time.AfterFunc(delay, func() {
				// TODO: handle error
				_, _ = p.conn.WriteToUDP(raw, conn.ClientAddr)
			})
		} else {
			_, err := p.conn.WriteToUDP(raw, conn.ClientAddr)
			if err != nil {
				return err
			}
		}
	}
}
