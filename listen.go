//go:build !linux
// +build !linux

package caddy

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Listen is like net.Listen, except Caddy's listeners can overlap
// each other: multiple listeners may be created on the same socket
// at the same time. This is useful because during config changes,
// the new config is started while the old config is still running.
// When Caddy listeners are closed, the closing logic is virtualized
// so the underlying socket isn't actually closed until all uses of
// the socket have been finished. Always be sure to close listeners
// when you are done with them, just like normal listeners.
func Listen(network, addr string) (net.Listener, error) {
	// a 0 timeout means Go uses its default
	return ListenTimeout(network, addr, 0)
}

func ListenTimeout(network, addr string, keepalivePeriod time.Duration) (net.Listener, error) {
	lnKey := network + "/" + addr + "/"

	sharedLn, _, err := listenerPool.LoadOrNew(lnKey, func() (Destructor, error) {
		ln, err := net.Listen(network, addr)

		if err != nil {
			// https://github.com/caddyserver/caddy/pull/4534
			if isUnixNetwork(network) && isListenBindAddressAlreadyInUseError(err) {
				return nil, fmt.Errorf("%w: this can happen if Caddy was forcefully killed", err)
			}
			return nil, err
		}
		return &sharedListener{Listener: ln, key: lnKey}, nil
	})
	if err != nil {
		return nil, err
	}

	return &fakeCloseListener{sharedListener: sharedLn.(*sharedListener), keepalivePeriod: keepalivePeriod}, nil
}

// typically applies only to TCP, but using interface for future proofing
type canSetKeepAlive interface {
	SetKeepAlivePeriod(d time.Duration) error
	SetKeepAlive(bool) error
}

// fakeCloseListener is a private wrapper over a listener that
// is shared. The state of fakeCloseListener is not shared.
// This allows one user of a socket to "close" the listener
// while in reality the socket stays open for other users of
// the listener. In this way, servers become hot-swappable
// while the listener remains running. Listeners should be
// re-wrapped in a new fakeCloseListener each time the listener
// is reused. This type is atomic and values must not be copied.
type fakeCloseListener struct {
	closed          int32 // accessed atomically; belongs to this struct only
	keepalivePeriod time.Duration
	*sharedListener // embedded, so we also become a net.Listener
}

func (fcl *fakeCloseListener) Accept() (net.Conn, error) {
	// if the listener is already "closed", return error
	if atomic.LoadInt32(&fcl.closed) == 1 {
		return nil, fakeClosedErr(fcl)
	}

	// call underlying accept
	conn, err := fcl.sharedListener.Accept()
	if err == nil {
		// if 0, do nothing, Go's default is already set
		if tconn, ok := conn.(canSetKeepAlive); ok && fcl.keepalivePeriod != 0 {
			if fcl.keepalivePeriod > 0 {
				tconn.SetKeepAlivePeriod(fcl.keepalivePeriod)
			} else { // negative
				tconn.SetKeepAlive(false)
			}
		}
		return conn, nil
	}

	// since Accept() returned an error, it may be because our reference to
	// the listener (this fakeCloseListener) may have been closed, i.e. the
	// server is shutting down; in that case, we need to clear the deadline
	// that we set when Close() was called, and return a non-temporary and
	// non-timeout error value to the caller, masking the "true" error, so
	// that server loops / goroutines won't retry, linger, and leak
	if atomic.LoadInt32(&fcl.closed) == 1 {
		// we dereference the sharedListener explicitly even though it's embedded
		// so that it's clear in the code that side-effects are shared with other
		// users of this listener, not just our own reference to it; we also don't
		// do anything with the error because all we could do is log it, but we
		// expliclty assign it to nothing so we don't forget it's there if needed
		_ = fcl.sharedListener.clearDeadline()

		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return nil, fakeClosedErr(fcl)
		}
	}

	return nil, err
}

// Close stops accepting new connections without closing the
// underlying listener. The underlying listener is only closed
// if the caller is the last known user of the socket.
func (fcl *fakeCloseListener) Close() error {
	if atomic.CompareAndSwapInt32(&fcl.closed, 0, 1) {
		// There are two ways I know of to get an Accept()
		// function to return to the server loop that called
		// it: close the listener, or set a deadline in the
		// past. Obviously, we can't close the socket yet
		// since others may be using it (hence this whole
		// file). But we can set the deadline in the past,
		// and this is kind of cheating, but it works, and
		// it apparently even works on Windows.
		_ = fcl.sharedListener.setDeadline()
		_, _ = listenerPool.Delete(fcl.sharedListener.key)
	}
	return nil
}

// sharedListener is a wrapper over an underlying listener. The listener
// and the other fields on the struct are shared state that is synchronized,
// so sharedListener structs must never be copied (always use a pointer).
type sharedListener struct {
	net.Listener
	key        string // uniquely identifies this listener
	deadline   bool   // whether a deadline is currently set
	deadlineMu sync.Mutex
}

func (sl *sharedListener) clearDeadline() error {
	var err error
	sl.deadlineMu.Lock()
	if sl.deadline {
		switch ln := sl.Listener.(type) {
		case *net.TCPListener:
			err = ln.SetDeadline(time.Time{})
		case *net.UnixListener:
			err = ln.SetDeadline(time.Time{})
		}
		sl.deadline = false
	}
	sl.deadlineMu.Unlock()
	return err
}

func (sl *sharedListener) setDeadline() error {
	timeInPast := time.Now().Add(-1 * time.Minute)
	var err error
	sl.deadlineMu.Lock()
	if !sl.deadline {
		switch ln := sl.Listener.(type) {
		case *net.TCPListener:
			err = ln.SetDeadline(timeInPast)
		case *net.UnixListener:
			err = ln.SetDeadline(timeInPast)
		}
		sl.deadline = true
	}
	sl.deadlineMu.Unlock()
	return err
}

// Destruct is called by the UsagePool when the listener is
// finally not being used anymore. It closes the socket.
func (sl *sharedListener) Destruct() error {
	return sl.Listener.Close()
}
