// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// TODO: Go 1.19 introduced the "unix" build tag. We have to support Go 1.18 until Go 1.20 is released.
// When Go 1.19 is our minimum, change this build tag to simply "!unix".
// (see similar change needed in listen_unix.go)
//go:build !(aix || android || darwin || dragonfly || freebsd || hurd || illumos || ios || linux || netbsd || openbsd || solaris)

package caddy

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

func reuseUnixSocket(network, addr string) (any, error) {
	return nil, nil
}

func listenTCPOrUnix(ctx context.Context, lnKey string, network, address string, config net.ListenConfig) (net.Listener, error) {
	sharedLn, _, err := listenerPool.LoadOrNew(lnKey, func() (Destructor, error) {
		ln, err := config.Listen(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return &sharedListener{Listener: ln, key: lnKey}, nil
	})
	if err != nil {
		return nil, err
	}
	return &fakeCloseListener{sharedListener: sharedLn.(*sharedListener), keepAlivePeriod: config.KeepAlive}, nil
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
	*sharedListener       // embedded, so we also become a net.Listener
	keepAlivePeriod time.Duration
}

type canSetKeepAlive interface {
	SetKeepAlivePeriod(d time.Duration) error
	SetKeepAlive(bool) error
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
		// and if the connection allows setting KeepAlive, set it
		if tconn, ok := conn.(canSetKeepAlive); ok && fcl.keepAlivePeriod != 0 {
			if fcl.keepAlivePeriod > 0 {
				err = tconn.SetKeepAlivePeriod(fcl.keepAlivePeriod)
			} else { // negative
				err = tconn.SetKeepAlive(false)
			}
			if err != nil {
				Log().With(zap.String("server", fcl.sharedListener.key)).Warn("unable to set keepalive for new connection:", zap.Error(err))
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
