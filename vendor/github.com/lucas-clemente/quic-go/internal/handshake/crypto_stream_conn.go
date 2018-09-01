package handshake

import (
	"bytes"
	"io"
	"net"
	"time"
)

// The CryptoStreamConn is used as the net.Conn passed to mint.
// It has two operating modes:
// 1. It can read and write to bytes.Buffers.
// 2. It can use a quic.Stream for reading and writing.
// The buffer-mode is only used by the server, in order to statelessly handle retries.
type CryptoStreamConn struct {
	remoteAddr net.Addr

	// the buffers are used before the session is initialized
	readBuf  bytes.Buffer
	writeBuf bytes.Buffer

	// stream will be set once the session is initialized
	stream io.ReadWriter
}

var _ net.Conn = &CryptoStreamConn{}

// NewCryptoStreamConn creates a new CryptoStreamConn
func NewCryptoStreamConn(remoteAddr net.Addr) *CryptoStreamConn {
	return &CryptoStreamConn{remoteAddr: remoteAddr}
}

func (c *CryptoStreamConn) Read(b []byte) (int, error) {
	if c.stream != nil {
		return c.stream.Read(b)
	}
	return c.readBuf.Read(b)
}

// AddDataForReading adds data to the read buffer.
// This data will ONLY be read when the stream has not been set.
func (c *CryptoStreamConn) AddDataForReading(data []byte) {
	c.readBuf.Write(data)
}

func (c *CryptoStreamConn) Write(p []byte) (int, error) {
	if c.stream != nil {
		return c.stream.Write(p)
	}
	return c.writeBuf.Write(p)
}

// GetDataForWriting returns all data currently in the write buffer, and resets this buffer.
func (c *CryptoStreamConn) GetDataForWriting() []byte {
	defer c.writeBuf.Reset()
	data := make([]byte, c.writeBuf.Len())
	copy(data, c.writeBuf.Bytes())
	return data
}

// SetStream sets the stream.
// After setting the stream, the read and write buffer won't be used any more.
func (c *CryptoStreamConn) SetStream(stream io.ReadWriter) {
	c.stream = stream
}

// Flush copies the contents of the write buffer to the stream
func (c *CryptoStreamConn) Flush() (int, error) {
	n, err := io.Copy(c.stream, &c.writeBuf)
	return int(n), err
}

// Close is not implemented
func (c *CryptoStreamConn) Close() error {
	return nil
}

// LocalAddr is not implemented
func (c *CryptoStreamConn) LocalAddr() net.Addr {
	return nil
}

// RemoteAddr returns the remote address
func (c *CryptoStreamConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

// SetReadDeadline is not implemented
func (c *CryptoStreamConn) SetReadDeadline(time.Time) error {
	return nil
}

// SetWriteDeadline is not implemented
func (c *CryptoStreamConn) SetWriteDeadline(time.Time) error {
	return nil
}

// SetDeadline is not implemented
func (c *CryptoStreamConn) SetDeadline(time.Time) error {
	return nil
}
