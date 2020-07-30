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

package logging

import (
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func init() {
	caddy.RegisterModule(NetWriter{})
}

// NetWriter implements a log writer that outputs to a network socket.
type NetWriter struct {
	Address string `json:"address,omitempty"`

	addr caddy.NetworkAddress
}

// CaddyModule returns the Caddy module information.
func (NetWriter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.logging.writers.net",
		New: func() caddy.Module { return new(NetWriter) },
	}
}

// Provision sets up the module.
func (nw *NetWriter) Provision(ctx caddy.Context) error {
	repl := caddy.NewReplacer()
	address, err := repl.ReplaceOrErr(nw.Address, true, true)
	if err != nil {
		return fmt.Errorf("invalid host in address: %v", err)
	}

	nw.addr, err = caddy.ParseNetworkAddress(address)
	if err != nil {
		return fmt.Errorf("parsing network address '%s': %v", address, err)
	}

	if nw.addr.PortRangeSize() != 1 {
		return fmt.Errorf("multiple ports not supported")
	}

	return nil
}

func (nw NetWriter) String() string {
	return nw.addr.String()
}

// WriterKey returns a unique key representing this nw.
func (nw NetWriter) WriterKey() string {
	return nw.addr.String()
}

// OpenWriter opens a new network connection.
func (nw NetWriter) OpenWriter() (io.WriteCloser, error) {
	reconn := &redialerConn{nw: nw}
	conn, err := reconn.dial()
	if err != nil {
		return nil, err
	}
	reconn.connMu.Lock()
	reconn.Conn = conn
	reconn.connMu.Unlock()
	return reconn, nil
}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens. Syntax:
//
//     net <address>
//
func (nw *NetWriter) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if !d.NextArg() {
			return d.ArgErr()
		}
		nw.Address = d.Val()
		if d.NextArg() {
			return d.ArgErr()
		}
	}
	return nil
}

// redialerConn wraps an underlying Conn so that if any
// writes fail, the connection is redialed and the write
// is retried.
type redialerConn struct {
	net.Conn
	connMu sync.RWMutex
	nw     NetWriter
}

// Write wraps the underlying Conn.Write method, but if that fails,
// it will re-dial the connection anew and try writing again.
func (reconn *redialerConn) Write(b []byte) (n int, err error) {
	reconn.connMu.RLock()
	conn := reconn.Conn
	reconn.connMu.RUnlock()
	if n, err = conn.Write(b); err == nil {
		return
	}

	// problem with the connection - lock it and try to fix it
	reconn.connMu.Lock()
	defer reconn.connMu.Unlock()

	// if multiple concurrent writes failed on the same broken conn, then
	// one of them might have already re-dialed by now; try writing again
	if n, err = reconn.Conn.Write(b); err == nil {
		return
	}

	// we're the lucky first goroutine to re-dial the connection
	conn2, err2 := reconn.dial()
	if err2 != nil {
		return
	}
	if n, err = conn2.Write(b); err == nil {
		reconn.Conn.Close()
		reconn.Conn = conn2
	}
	return
}

func (reconn *redialerConn) dial() (net.Conn, error) {
	return net.Dial(reconn.nw.addr.Network, reconn.nw.addr.JoinHostPort(0))
}

// Interface guards
var (
	_ caddy.Provisioner     = (*NetWriter)(nil)
	_ caddy.WriterOpener    = (*NetWriter)(nil)
	_ caddyfile.Unmarshaler = (*NetWriter)(nil)
)
