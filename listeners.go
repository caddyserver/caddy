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

package caddy

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// TODO: Can we use the new UsagePool type?

// Listen returns a listener suitable for use in a Caddy module.
// Always be sure to close listeners when you are done with them.
func Listen(network, addr string) (net.Listener, error) {
	lnKey := network + "/" + addr

	listenersMu.Lock()
	defer listenersMu.Unlock()

	// if listener already exists, increment usage counter, then return listener
	if lnUsage, ok := listeners[lnKey]; ok {
		atomic.AddInt32(&lnUsage.usage, 1)
		return &fakeCloseListener{usage: &lnUsage.usage, key: lnKey, Listener: lnUsage.ln}, nil
	}

	// or, create new one and save it
	ln, err := net.Listen(network, addr)
	if err != nil {
		return nil, err
	}

	// make sure to start its usage counter at 1
	lnUsage := &listenerUsage{usage: 1, ln: ln}
	listeners[lnKey] = lnUsage

	return &fakeCloseListener{usage: &lnUsage.usage, key: lnKey, Listener: ln}, nil
}

// ListenPacket returns a net.PacketConn suitable for use in a Caddy module.
// Always be sure to close the PacketConn when you are done.
func ListenPacket(network, addr string) (net.PacketConn, error) {
	lnKey := network + "/" + addr

	listenersMu.Lock()
	defer listenersMu.Unlock()

	// if listener already exists, increment usage counter, then return listener
	if lnUsage, ok := listeners[lnKey]; ok {
		atomic.AddInt32(&lnUsage.usage, 1)
		log.Printf("[DEBUG] %s: Usage counter should not go above 2 or maybe 3, is now: %d", lnKey, atomic.LoadInt32(&lnUsage.usage)) // TODO: remove
		return &fakeClosePacketConn{usage: &lnUsage.usage, key: lnKey, PacketConn: lnUsage.pc}, nil
	}

	// or, create new one and save it
	pc, err := net.ListenPacket(network, addr)
	if err != nil {
		return nil, err
	}

	// make sure to start its usage counter at 1
	lnUsage := &listenerUsage{usage: 1, pc: pc}
	listeners[lnKey] = lnUsage

	return &fakeClosePacketConn{usage: &lnUsage.usage, key: lnKey, PacketConn: pc}, nil
}

// fakeCloseListener's Close() method is a no-op. This allows
// stopping servers that are using the listener without giving
// up the socket; thus, servers become hot-swappable while the
// listener remains running. Listeners should be re-wrapped in
// a new fakeCloseListener each time the listener is reused.
type fakeCloseListener struct {
	closed int32  // accessed atomically - TODO: this needs to be shared across the whole app instance, not to cross instance boundaries... hmmm... see #2658 (still relevant?)
	usage  *int32 // accessed atomically
	key    string
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

// Close stops accepting new connections without
// closing the underlying listener, unless no one
// else is using it.
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

		// since we're no longer using this listener,
		// decrement the usage counter and, if no one
		// else is using it, close underlying listener
		if atomic.AddInt32(fcl.usage, -1) == 0 {
			listenersMu.Lock()
			delete(listeners, fcl.key)
			listenersMu.Unlock()
			err := fcl.Listener.Close()
			if err != nil {
				return err
			}
		}

	}

	return nil
}

func (fcl *fakeCloseListener) fakeClosedErr() error {
	return &net.OpError{
		Op:   "accept",
		Net:  fcl.Listener.Addr().Network(),
		Addr: fcl.Listener.Addr(),
		Err:  errFakeClosed,
	}
}

type fakeClosePacketConn struct {
	closed int32  // accessed atomically - TODO: this needs to be shared across the whole app instance, not to cross instance boundaries... hmmm... see #2658 (still relevant?)
	usage  *int32 // accessed atomically
	key    string
	net.PacketConn
}

func (fcpc *fakeClosePacketConn) Close() error {
	log.Println("[DEBUG] Fake-closing underlying packet conn") // TODO: remove this

	if atomic.CompareAndSwapInt32(&fcpc.closed, 0, 1) {
		// since we're no longer using this listener,
		// decrement the usage counter and, if no one
		// else is using it, close underlying listener
		if atomic.AddInt32(fcpc.usage, -1) == 0 {
			listenersMu.Lock()
			delete(listeners, fcpc.key)
			listenersMu.Unlock()
			err := fcpc.PacketConn.Close()
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// ErrFakeClosed is the underlying error value returned by
// fakeCloseListener.Accept() after Close() has been called,
// indicating that it is pretending to be closed so that the
// server using it can terminate, while the underlying
// socket is actually left open.
var errFakeClosed = fmt.Errorf("listener 'closed' 😉")

// listenerUsage pairs a net.Listener with a
// count of how many servers are using it.
type listenerUsage struct {
	usage int32 // accessed atomically
	ln    net.Listener
	pc    net.PacketConn
}

var (
	listeners   = make(map[string]*listenerUsage)
	listenersMu sync.Mutex
)

// ParseNetworkAddress parses addr, a string of the form "network/host:port"
// (with any part optional) into its component parts. Because a port can
// also be a port range, there may be multiple addresses returned.
func ParseNetworkAddress(addr string) (network string, addrs []string, err error) {
	var host, port string
	network, host, port, err = SplitNetworkAddress(addr)
	if network == "" {
		network = "tcp"
	}
	if err != nil {
		return
	}
	if network == "unix" || network == "unixgram" || network == "unixpacket" {
		addrs = []string{host}
		return
	}
	ports := strings.SplitN(port, "-", 2)
	if len(ports) == 1 {
		ports = append(ports, ports[0])
	}
	var start, end int
	start, err = strconv.Atoi(ports[0])
	if err != nil {
		return
	}
	end, err = strconv.Atoi(ports[1])
	if err != nil {
		return
	}
	if end < start {
		err = fmt.Errorf("end port must be greater than start port")
		return
	}
	for p := start; p <= end; p++ {
		addrs = append(addrs, net.JoinHostPort(host, fmt.Sprintf("%d", p)))
	}
	return
}

// SplitNetworkAddress splits a into its network, host, and port components.
// Note that port may be a port range, or omitted for unix sockets.
func SplitNetworkAddress(a string) (network, host, port string, err error) {
	if idx := strings.Index(a, "/"); idx >= 0 {
		network = strings.ToLower(strings.TrimSpace(a[:idx]))
		a = a[idx+1:]
	}
	if network == "unix" || network == "unixgram" || network == "unixpacket" {
		host = a
		return
	}
	host, port, err = net.SplitHostPort(a)
	return
}

// JoinNetworkAddress combines network, host, and port into a single
// address string of the form "network/host:port". Port may be a
// port range. For unix sockets, the network should be "unix" and
// the path to the socket should be given in the host argument.
func JoinNetworkAddress(network, host, port string) string {
	var a string
	if network != "" {
		a = network + "/"
	}
	if host != "" && port == "" {
		a += host
	} else if port != "" {
		a += net.JoinHostPort(host, port)
	}
	return a
}
