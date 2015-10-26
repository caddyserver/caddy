package server

import (
	"net"
	"os"
	"sync"
	"syscall"
)

// newGracefulListener returns a gracefulListener that wraps l and
// uses wg (stored in the host server) to count connections.
func newGracefulListener(l ListenerFile, wg *sync.WaitGroup) *gracefulListener {
	gl := &gracefulListener{ListenerFile: l, stop: make(chan error), httpWg: wg}
	go func() {
		<-gl.stop
		gl.stopped = true
		gl.stop <- gl.ListenerFile.Close()
	}()
	return gl
}

// gracefuListener is a net.Listener which can
// count the number of connections on it. Its
// methods mainly wrap net.Listener to be graceful.
type gracefulListener struct {
	ListenerFile
	stop    chan error
	stopped bool
	httpWg  *sync.WaitGroup // pointer to the host's wg used for counting connections
}

// Accept accepts a connection. This type wraps
func (gl *gracefulListener) Accept() (c net.Conn, err error) {
	c, err = gl.ListenerFile.Accept()
	if err != nil {
		return
	}
	c = gracefulConn{Conn: c, httpWg: gl.httpWg}
	gl.httpWg.Add(1)
	return
}

// Close immediately closes the listener.
func (gl *gracefulListener) Close() error {
	if gl.stopped {
		return syscall.EINVAL
	}
	gl.stop <- nil
	return <-gl.stop
}

// File implements ListenerFile; it gets the file of the listening socket.
func (gl *gracefulListener) File() (*os.File, error) {
	return gl.ListenerFile.File()
}

// gracefulConn represents a connection on a
// gracefulListener so that we can keep track
// of the number of connections, thus facilitating
// a graceful shutdown.
type gracefulConn struct {
	net.Conn
	httpWg *sync.WaitGroup // pointer to the host server's connection waitgroup
}

// Close closes c's underlying connection while updating the wg count.
func (c gracefulConn) Close() error {
	c.httpWg.Done()
	return c.Conn.Close()
}
