package caddy2

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Listen returns a listener suitable for use in a Caddy module.
func Listen(network, addr string) (net.Listener, error) {
	lnKey := network + "/" + addr

	listenersMu.Lock()
	defer listenersMu.Unlock()

	// if listener already exists, return it
	if ln, ok := listeners[lnKey]; ok {
		return &fakeCloseListener{Listener: ln}, nil
	}

	// or, create new one and save it
	ln, err := net.Listen(network, addr)
	if err != nil {
		return nil, err
	}
	listeners[lnKey] = ln

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
	// if the listener is already "closed", return error
	if atomic.LoadInt32(&fcl.closed) == 1 {
		return nil, fcl.fakeClosedErr()
	}

	// wrap underlying accept
	conn, err := fcl.Listener.Accept()
	if err == nil {
		return conn, nil
	}

	if atomic.LoadInt32(&fcl.closed) == 1 {
		// clear the deadline
		switch ln := fcl.Listener.(type) {
		case *net.TCPListener:
			ln.SetDeadline(time.Time{})
		case *net.UnixListener:
			ln.SetDeadline(time.Time{})
		}

		// if we cancelled the Accept() by setting a deadline
		// on the listener, we need to make sure any callers of
		// Accept() think the listener was actually closed;
		// if we return the timeout error instead, callers might
		// simply retry, leaking goroutines for longer
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return nil, fcl.fakeClosedErr()
		}
	}

	return nil, err
}

// Close stops accepting new connections, but does not
// actually close the underlying listener.
func (fcl *fakeCloseListener) Close() error {
	if atomic.CompareAndSwapInt32(&fcl.closed, 0, 1) {
		// unfortunately, there is no way to cancel any
		// currently-blocking calls to Accept() that are
		// awaiting connections since we're not actually
		// closing the listener; so we cheat by setting
		// a deadline in the past, which forces it to
		// time out; note that this only works for
		// certain types of listeners...
		switch ln := fcl.Listener.(type) {
		case *net.TCPListener:
			ln.SetDeadline(time.Now().Add(-1 * time.Minute))
		case *net.UnixListener:
			ln.SetDeadline(time.Now().Add(-1 * time.Minute))
		}
	}

	return nil
}

// CloseUnderlying actually closes the underlying listener.
func (fcl *fakeCloseListener) CloseUnderlying() error {
	return fcl.Listener.Close()
}

func (fcl *fakeCloseListener) fakeClosedErr() error {
	return &net.OpError{
		Op:   "accept",
		Net:  fcl.Listener.Addr().Network(),
		Addr: fcl.Listener.Addr(),
		Err:  ErrFakeClosed,
	}
}

// ErrFakeClosed is the underlying error value returned by
// fakeCloseListener.Accept() after Close() has been called,
// indicating that it is pretending to be closed so that the
// server using it can terminate, while the underlying
// socket is actually left open.
var ErrFakeClosed = fmt.Errorf("listener 'closed' 😉")

var (
	listeners   = make(map[string]net.Listener)
	listenersMu sync.Mutex
)
