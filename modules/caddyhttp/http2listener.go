package caddyhttp

import (
	"crypto/tls"
	"go.uber.org/zap"
	"io"
	"net"

	"golang.org/x/net/http2"
)

type connectionStater interface {
	ConnectionState() tls.ConnectionState
}

// http2Listener wraps the listener to solve the following problems:
// 1. prevent genuine h2c connections from succeeding if h2c is not enabled
// and the connection doesn't implment connectionStater or the resulting NegotiatedProtocol
// isn't http2.
// This does allow a connection to pass as tls enabled even if it's not, listener wrappers
// can do this.
// 2. After wrapping the connection doesn't implement connectionStater, emit a warning so that listener
// wrapper authors will hopefully implement it.
type http2Listener struct {
	useTLS bool
	net.Listener
	logger *zap.Logger
}

func (h *http2Listener) Accept() (net.Conn, error) {
	conn, err := h.Listener.Accept()
	if err != nil {
		return nil, err
	}

	if h.useTLS {
		// emit a warning
		if _, ok := conn.(connectionStater); !ok {
			h.logger.Warn("tls is enabled, but listener wrapper returns a connection that doesn't implement connectionStater")
		}
		return &http2Conn{
			idx:  len(http2.ClientPreface),
			Conn: conn,
		}, nil
	}

	if _, ok := conn.(connectionStater); ok {
		h.logger.Warn("tls is disabled, but listener wrapper returns a connection that implements connectionStater")
		return &http2Conn{
			idx:  len(http2.ClientPreface),
			Conn: conn,
		}, nil
	}

	return &http2Conn{
		Conn: conn,
	}, nil
}

type http2Conn struct {
	// check h2 preface if it's smaller that the preface
	idx int
	// log if one such connection is detected
	logger *zap.Logger
	net.Conn
}

func (c *http2Conn) Read(p []byte) (int, error) {
	if c.idx >= len(http2.ClientPreface) {
		return c.Conn.Read(p)
	}
	n, err := c.Conn.Read(p)
	for i := range n {
		// mismatch
		if p[i] != http2.ClientPreface[c.idx] {
			c.idx = len(http2.ClientPreface)
			return n, err
		}
		c.idx++
		if c.idx == len(http2.ClientPreface) {
			c.logger.Warn("h2c connection detected, but h2c is not enabled")
			_ = c.Conn.Close()
			return 0, io.EOF
		}
	}
	return n, err
}
