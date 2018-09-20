package handshake

import (
	"bytes"
	"io"
	"net"
	"time"
)

type cryptoStreamConn struct {
	buffer *bytes.Buffer
	stream io.ReadWriter
}

var _ net.Conn = &cryptoStreamConn{}

func newCryptoStreamConn(stream io.ReadWriter) *cryptoStreamConn {
	return &cryptoStreamConn{
		stream: stream,
		buffer: &bytes.Buffer{},
	}
}

func (c *cryptoStreamConn) Read(b []byte) (int, error) {
	return c.stream.Read(b)
}

func (c *cryptoStreamConn) Write(p []byte) (int, error) {
	return c.buffer.Write(p)
}

func (c *cryptoStreamConn) Flush() error {
	if c.buffer.Len() == 0 {
		return nil
	}
	_, err := c.stream.Write(c.buffer.Bytes())
	c.buffer.Reset()
	return err
}

// Close is not implemented
func (c *cryptoStreamConn) Close() error {
	return nil
}

// LocalAddr is not implemented
func (c *cryptoStreamConn) LocalAddr() net.Addr {
	return nil
}

// RemoteAddr is not implemented
func (c *cryptoStreamConn) RemoteAddr() net.Addr {
	return nil
}

// SetReadDeadline is not implemented
func (c *cryptoStreamConn) SetReadDeadline(time.Time) error {
	return nil
}

// SetWriteDeadline is not implemented
func (c *cryptoStreamConn) SetWriteDeadline(time.Time) error {
	return nil
}

// SetDeadline is not implemented
func (c *cryptoStreamConn) SetDeadline(time.Time) error {
	return nil
}
