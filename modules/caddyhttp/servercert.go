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
	"crypto/x509"
	"net"
	"sync"

	"github.com/caddyserver/caddy/v2"
)

// ServerCertCtxKey is the context key for the server certificate.
// The value in the context can be an *x509.Certificate or a func() *x509.Certificate.
const ServerCertCtxKey caddy.CtxKey = "tls_server_cert"

type serverCertHolder interface {
	SetServerCertificate(*x509.Certificate)
	ServerCertificate() *x509.Certificate
}

// tlsServerConn wraps a net.Conn to record the server certificate selected during TLS handshake.
type tlsServerConn struct {
	net.Conn
	mu   sync.Mutex
	cert *x509.Certificate
}

func (c *tlsServerConn) SetServerCertificate(cert *x509.Certificate) {
	c.mu.Lock()
	c.cert = cert
	c.mu.Unlock()
}

func (c *tlsServerConn) ServerCertificate() *x509.Certificate {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cert
}

func (c *tlsServerConn) Unwrap() net.Conn {
	return c.Conn
}

// tlsServerCertListener wraps a net.Listener so accepted connections are wrapped with tlsServerConn.
type tlsServerCertListener struct {
	net.Listener
}

func (l *tlsServerCertListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &tlsServerConn{Conn: c}, nil
}

func findServerCertHolder(c net.Conn) serverCertHolder {
	for c != nil {
		if h, ok := c.(serverCertHolder); ok {
			return h
		}
		if u, ok := c.(interface{ tlsNetConn() net.Conn }); ok {
			c = u.tlsNetConn()
		} else if u, ok := c.(interface{ Unwrap() net.Conn }); ok {
			c = u.Unwrap()
		} else if u, ok := c.(interface{ NetConn() net.Conn }); ok {
			c = u.NetConn()
		} else {
			break
		}
	}
	return nil
}
