package httpserver

import (
	"net"
	"sync"
	"syscall"
)

// TODO: Should this be a generic graceful listener available in its own package or something?
// Also, passing in a WaitGroup is a little awkward. Why can't this listener just keep
// the waitgroup internal to itself?

// newGracefulListener returns a gracefulListener that wraps l and
// uses wg (stored in the host server) to count connections.
func newGracefulListener(l net.Listener, wg *sync.WaitGroup) *gracefulListener {
	gl := &gracefulListener{Listener: l, stop: make(chan error), connWg: wg}
	go func() {
		<-gl.stop
		gl.Lock()
		gl.stopped = true
		gl.Unlock()
		gl.stop <- gl.Listener.Close()
	}()
	return gl
}

// gracefuListener is a net.Listener which can
// count the number of connections on it. Its
// methods mainly wrap net.Listener to be graceful.
type gracefulListener struct {
	net.Listener
	stop       chan error
	stopped    bool
	sync.Mutex                 // protects the stopped flag
	connWg     *sync.WaitGroup // pointer to the host's wg used for counting connections
}

// Accept accepts a connection.
func (gl *gracefulListener) Accept() (c net.Conn, err error) {
	c, err = gl.Listener.Accept()
	if err != nil {
		return
	}
	c = gracefulConn{Conn: c, connWg: gl.connWg}
	gl.connWg.Add(1)
	return
}

// Close immediately closes the listener.
func (gl *gracefulListener) Close() error {
	gl.Lock()
	if gl.stopped {
		gl.Unlock()
		return syscall.EINVAL
	}
	gl.Unlock()
	gl.stop <- nil
	return <-gl.stop
}

// gracefulConn represents a connection on a
// gracefulListener so that we can keep track
// of the number of connections, thus facilitating
// a graceful shutdown.
type gracefulConn struct {
	net.Conn
	connWg *sync.WaitGroup // pointer to the host server's connection waitgroup
}

// Close closes c's underlying connection while updating the wg count.
func (c gracefulConn) Close() error {
	err := c.Conn.Close()
	if err != nil {
		return err
	}
	// close can fail on http2 connections (as of Oct. 2015, before http2 in std lib)
	// so don't decrement count unless close succeeds
	c.connWg.Done()
	return nil
}
