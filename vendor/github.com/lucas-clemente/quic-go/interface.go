package quic

import (
	"crypto/tls"
	"io"
	"net"
	"time"

	"github.com/lucas-clemente/quic-go/protocol"
)

// Stream is the interface implemented by QUIC streams
type Stream interface {
	io.Reader
	io.Writer
	io.Closer
	StreamID() protocol.StreamID
	// Reset closes the stream with an error.
	Reset(error)
}

// A Session is a QUIC connection between two peers.
type Session interface {
	// AcceptStream returns the next stream opened by the peer, blocking until one is available.
	// Since stream 1 is reserved for the crypto stream, the first stream is either 2 (for a client) or 3 (for a server).
	AcceptStream() (Stream, error)
	// OpenStream opens a new QUIC stream, returning a special error when the peeer's concurrent stream limit is reached.
	// New streams always have the smallest possible stream ID.
	// TODO: Enable testing for the special error
	OpenStream() (Stream, error)
	// OpenStreamSync opens a new QUIC stream, blocking until the peer's concurrent stream limit allows a new stream to be opened.
	// It always picks the smallest possible stream ID.
	OpenStreamSync() (Stream, error)
	// LocalAddr returns the local address.
	LocalAddr() net.Addr
	// RemoteAddr returns the address of the peer.
	RemoteAddr() net.Addr
	// Close closes the connection. The error will be sent to the remote peer in a CONNECTION_CLOSE frame. An error value of nil is allowed and will cause a normal PeerGoingAway to be sent.
	Close(error) error
}

// A NonFWSession is a QUIC connection between two peers half-way through the handshake.
// The communication is encrypted, but not yet forward secure.
type NonFWSession interface {
	Session
	WaitUntilHandshakeComplete() error
}

// An STK is a Source Address token.
// It is issued by the server and sent to the client. For the client, it is an opaque blob.
// The client can send the STK in subsequent handshakes to prove ownership of its IP address.
type STK struct {
	// The remote address this token was issued for.
	// If the server is run on a net.UDPConn, this is the string representation of the IP address (net.IP.String())
	// Otherwise, this is the string representation of the net.Addr (net.Addr.String())
	remoteAddr string
	// The time that the STK was issued (resolution 1 second)
	sentTime time.Time
}

// Config contains all configuration data needed for a QUIC server or client.
// More config parameters (such as timeouts) will be added soon, see e.g. https://github.com/lucas-clemente/quic-go/issues/441.
type Config struct {
	TLSConfig *tls.Config
	// The QUIC versions that can be negotiated.
	// If not set, it uses all versions available.
	// Warning: This API should not be considered stable and will change soon.
	Versions []protocol.VersionNumber
	// Ask the server to truncate the connection ID sent in the Public Header.
	// If not set, the default checks if
	// This saves 8 bytes in the Public Header in every packet. However, if the IP address of the server changes, the connection cannot be migrated.
	// Currently only valid for the client.
	RequestConnectionIDTruncation bool
	// AcceptSTK determines if an STK is accepted.
	// It is called with stk = nil if the client didn't send an STK.
	// If not set, it verifies that the address matches, and that the STK was issued within the last 24 hours
	// This option is only valid for the server.
	AcceptSTK func(clientAddr net.Addr, stk *STK) bool
}

// A Listener for incoming QUIC connections
type Listener interface {
	// Close the server, sending CONNECTION_CLOSE frames to each peer.
	Close() error
	// Addr returns the local network addr that the server is listening on.
	Addr() net.Addr
	// Accept returns new sessions. It should be called in a loop.
	Accept() (Session, error)
}
