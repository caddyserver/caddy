package caddy2

import (
	"fmt"
	"net"
	"sync/atomic"
)

// Listen returns a listener suitable for use in a Caddy module.
func Listen(proto, addr string) (net.Listener, error) {
	ln, err := net.Listen(proto, addr)
	if err != nil {
		return nil, err
	}
	return &fakeCloseListener{Listener: ln}, nil
}

// fakeCloseListener's Close() method is a no-op. This allows
// stopping servers that are using the listener without giving
// up the socket; thus, servers become hot-swappable while the
// listener remains running. Listeners should be re-wrapped in
// a new fakeCloseListener each time the listener is reused.
type fakeCloseListener struct {
	closed int32
	net.Listener
}

// Accept accepts connections until Close() is called.
func (fcl *fakeCloseListener) Accept() (net.Conn, error) {
	if atomic.LoadInt32(&fcl.closed) == 1 {
		return nil, ErrSwappingServers
	}
	return fcl.Listener.Accept()
}

// Close stops accepting new connections, but does not
// actually close the underlying listener.
func (fcl *fakeCloseListener) Close() error {
	atomic.StoreInt32(&fcl.closed, 1)
	return nil
}

// CloseUnderlying actually closes the underlying listener.
func (fcl *fakeCloseListener) CloseUnderlying() error {
	return fcl.Listener.Close()
}

// ErrSwappingServers is returned by fakeCloseListener when
// Close() is called, indicating that it is pretending to
// be closed so that the server using it can terminate.
var ErrSwappingServers = fmt.Errorf("listener 'closed' 😉")
