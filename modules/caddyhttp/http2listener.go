package caddyhttp

import (
	"crypto/tls"
	"io"
	"net"

	"go.uber.org/zap"
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
// 3. check if the connection matches a specific http version. h2/h2c has a distinct preface.
type http2Listener struct {
	useTLS bool
	useH1  bool
	useH2  bool
	net.Listener
	logger *zap.Logger
}

func (h *http2Listener) Accept() (net.Conn, error) {
	conn, err := h.Listener.Accept()
	if err != nil {
		return nil, err
	}

	_, isConnectionStater := conn.(connectionStater)
	// emit a warning
	if h.useTLS && !isConnectionStater {
		h.logger.Warn("tls is enabled, but listener wrapper returns a connection that doesn't implement connectionStater")
	} else if !h.useTLS && isConnectionStater {
		h.logger.Warn("tls is disabled, but listener wrapper returns a connection that implements connectionStater")
	}

	// if both h1 and h2 are enabled, we don't need to check the preface
	if h.useH1 && h.useH2 {
		return &http2Conn{
			idx:  len(http2.ClientPreface),
			Conn: conn,
		}, nil
	}

	// impossible both are false, either useH1 or useH2 must be true,
	// or else the listener wouldn't be created
	return &http2Conn{
		h2Expected: h.useH2,
		Conn:       conn,
	}, nil
}

type http2Conn struct {
	// current index where the preface should match,
	// no matching is done if idx is >= len(http2.ClientPreface)
	idx int
	// whether the connection is expected to be h2/h2c
	h2Expected bool
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
		// first mismatch, close the connection if h2 is expected
		if p[i] != http2.ClientPreface[c.idx] && c.h2Expected {
			c.logger.Debug("h1 connection detected, but h1 is not enabled")
			_ = c.Conn.Close()
			return 0, io.EOF
		}
		c.idx++
		// matching complete
		if c.idx == len(http2.ClientPreface) && !c.h2Expected {
			c.logger.Debug("h2/h2c connection detected, but h2/h2c is not enabled")
			_ = c.Conn.Close()
			return 0, io.EOF
		}
	}
	return n, err
}
