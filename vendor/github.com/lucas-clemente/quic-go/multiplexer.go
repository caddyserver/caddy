package quic

import (
	"fmt"
	"net"
	"sync"

	"github.com/lucas-clemente/quic-go/internal/utils"
)

var (
	connMuxerOnce sync.Once
	connMuxer     multiplexer
)

type multiplexer interface {
	AddConn(net.PacketConn, int) (packetHandlerManager, error)
}

type connManager struct {
	connIDLen int
	manager   packetHandlerManager
}

// The connMultiplexer listens on multiple net.PacketConns and dispatches
// incoming packets to the session handler.
type connMultiplexer struct {
	mutex sync.Mutex

	conns                   map[net.PacketConn]connManager
	newPacketHandlerManager func(net.PacketConn, int, utils.Logger) packetHandlerManager // so it can be replaced in the tests

	logger utils.Logger
}

var _ multiplexer = &connMultiplexer{}

func getMultiplexer() multiplexer {
	connMuxerOnce.Do(func() {
		connMuxer = &connMultiplexer{
			conns:                   make(map[net.PacketConn]connManager),
			logger:                  utils.DefaultLogger.WithPrefix("muxer"),
			newPacketHandlerManager: newPacketHandlerMap,
		}
	})
	return connMuxer
}

func (m *connMultiplexer) AddConn(c net.PacketConn, connIDLen int) (packetHandlerManager, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	p, ok := m.conns[c]
	if !ok {
		manager := m.newPacketHandlerManager(c, connIDLen, m.logger)
		p = connManager{connIDLen: connIDLen, manager: manager}
		m.conns[c] = p
	}
	if p.connIDLen != connIDLen {
		return nil, fmt.Errorf("cannot use %d byte connection IDs on a connection that is already using %d byte connction IDs", connIDLen, p.connIDLen)
	}
	return p.manager, nil
}
