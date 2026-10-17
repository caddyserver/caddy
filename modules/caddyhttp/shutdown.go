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

package caddyhttp

import (
	"context"
	"errors"
	"net"
	"net/http"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
)

// http.Server.Shutdown marks the server as shutting down before it closes
// its listeners, and net/http closes without a response any HTTP/1 request
// it finishes reading after that. A connection accepted before Shutdown
// whose request had not been read yet, or one accepted between those two
// steps, was closed unanswered on every config reload (#8233). So before
// calling Shutdown, stopAccepting closes the HTTP/1 and HTTP/2 listeners,
// waits for their Serve loops to return, and then waits for the connections
// those loops accepted to send their first request.

// newConnMaxWait is how long a connection that sends nothing is waited for.
// http.Server.Shutdown treats a connection that is still in StateNew after
// 5 seconds as idle and closes it (golang/go#22682), so waiting up to as
// long does not make a shutdown slower than it was.
const newConnMaxWait = 5 * time.Second

// serve runs s.server's accept loop on ln.
func (s *Server) serve(ln net.Listener) {
	oln := &onceCloseListener{Listener: ln}
	s.serveListeners = append(s.serveListeners, oln)
	s.serveLoops.Add(1)
	go func() {
		defer s.serveLoops.Done()
		//nolint:errcheck
		s.server.Serve(oln)
	}()
}

// stopAccepting closes s's HTTP/1 and HTTP/2 listeners, waits for their
// Serve loops to return, then waits until every connection they accepted
// has had its first request reach ServeHTTP or closed (see
// newConnTracker), was accepted newConnMaxWait ago, or ctx is done.
// It returns the errors from closing the listeners.
func (s *Server) stopAccepting(ctx context.Context) error {
	var errs []error
	for _, ln := range s.serveListeners {
		if err := ln.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	// ConnState(StateNew) runs in the accept loop, so once the loops have
	// returned, every connection they accepted is tracked
	loopsDone := make(chan struct{})
	go func() {
		s.serveLoops.Wait()
		close(loopsDone)
	}()
	select {
	case <-loopsDone:
		s.newConns.wait(ctx)
	case <-ctx.Done():
	}
	return errors.Join(errs...)
}

// onceCloseListener closes its listener once: stopAccepting closes it
// before Shutdown and Serve's deferred Close do, and on Unix each Close of
// a deleteListener releases a use of the pooled socket.
type onceCloseListener struct {
	net.Listener
	once sync.Once
}

func (l *onceCloseListener) Close() error {
	var err error
	l.once.Do(func() { err = l.Listener.Close() })
	return err
}

// newConnTracker tracks the connections a server accepted (StateNew) until
// their first request reaches ServeHTTP, they are hijacked, or they close.
// Leaving StateNew is not enough on its own:
//   - net/http sets StateActive on an HTTP/1 connection after reading its
//     request but before checking whether the server is shutting down, and
//     closes the connection without a response if it is;
//   - an HTTP/2 connection goes StateActive and then StateIdle as soon as
//     the client preface is read, so Shutdown's GOAWAY would refuse its
//     first request (which a client can only retry elsewhere, and not at
//     all if the new config removed the address).
type newConnTracker struct {
	mu      sync.Mutex
	conns   map[net.Conn]time.Time // when each connection was accepted
	changed chan struct{}          // closed when a connection is untracked
}

// connState is the server's http.Server.ConnState. StateNew is reported
// in the accept loop, before Serve can return.
func (t *newConnTracker) connState(c net.Conn, state http.ConnState) {
	switch state {
	case http.StateNew:
		// a listener wrapper's connection might not be usable as a map
		// key; such a connection is not waited for
		if !reflect.ValueOf(c).Comparable() {
			return
		}
		t.mu.Lock()
		if t.conns == nil {
			t.conns = make(map[net.Conn]time.Time)
		}
		t.conns[c] = time.Now()
		t.mu.Unlock()
	case http.StateHijacked, http.StateClosed:
		t.untrack(c)
	}
	if hook := testHookNewConnState.Load(); hook != nil {
		(*hook)(c, state)
	}
}

// connContext is called with the server's http.Server.ConnContext; it
// lets ServeHTTP find a request's connection.
func (t *newConnTracker) connContext(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, newConnCtxKey, &newConn{conn: c})
}

// requestSeen untracks r's connection: its first request reached
// ServeHTTP, past net/http's HTTP/1 shutdown check, and for HTTP/2 within
// the streams a GOAWAY lets finish.
func (t *newConnTracker) requestSeen(r *http.Request) {
	if nc, ok := r.Context().Value(newConnCtxKey).(*newConn); ok && !nc.seen.Load() && nc.seen.CompareAndSwap(false, true) {
		t.untrack(nc.conn)
	}
}

func (t *newConnTracker) untrack(c net.Conn) {
	if !reflect.ValueOf(c).Comparable() {
		return
	}
	t.mu.Lock()
	if _, ok := t.conns[c]; ok {
		delete(t.conns, c)
		if t.changed != nil {
			close(t.changed)
			t.changed = nil
		}
	}
	t.mu.Unlock()
}

// wait returns once no connection accepted less than newConnMaxWait ago
// is tracked, or when ctx is done.
func (t *newConnTracker) wait(ctx context.Context) {
	for {
		t.mu.Lock()
		now := time.Now()
		var pending int
		var next time.Duration // until the oldest pending connection's wait is over
		for _, accepted := range t.conns {
			left := newConnMaxWait - now.Sub(accepted)
			if left <= 0 {
				continue
			}
			if pending == 0 || left < next {
				next = left
			}
			pending++
		}
		if pending == 0 {
			t.mu.Unlock()
			return
		}
		if t.changed == nil {
			t.changed = make(chan struct{})
		}
		changed := t.changed
		t.mu.Unlock()

		if hook := testHookAwaitNewConns.Load(); hook != nil {
			(*hook)(pending)
		}
		timer := time.NewTimer(next)
		select {
		case <-changed:
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return
		}
		timer.Stop()
	}
}

// newConn is the newConnCtxKey value of a connection's context.
type newConn struct {
	conn net.Conn
	seen atomic.Bool
}

const newConnCtxKey caddy.CtxKey = "new_conn"

// Test hooks: testHookNewConnState is called after the tracker handled a
// connection state change, on the goroutine that reported it, and
// testHookAwaitNewConns before stopAccepting blocks on pending connections.
var (
	testHookNewConnState  atomic.Pointer[func(net.Conn, http.ConnState)]
	testHookAwaitNewConns atomic.Pointer[func(pending int)]
)
