package handshake

import (
	"crypto/x509"
	"io"

	"github.com/bifurcation/mint"
	"github.com/lucas-clemente/quic-go/internal/crypto"
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

// Sealer seals a packet
type Sealer interface {
	Seal(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) []byte
	Overhead() int
}

// A TLSExtensionHandler sends and received the QUIC TLS extension.
// It provides the parameters sent by the peer on a channel.
type TLSExtensionHandler interface {
	Send(mint.HandshakeType, *mint.ExtensionList) error
	Receive(mint.HandshakeType, *mint.ExtensionList) error
	GetPeerParams() <-chan TransportParameters
}

// MintTLS combines some methods needed to interact with mint.
type MintTLS interface {
	crypto.TLSExporter

	// additional methods
	Handshake() mint.Alert
	State() mint.State
	ConnectionState() mint.ConnectionState

	SetCryptoStream(io.ReadWriter)
}

// CryptoSetup is a crypto setup
type CryptoSetup interface {
	Open(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, protocol.EncryptionLevel, error)
	HandleCryptoStream() error
	// TODO: clean up this interface
	DiversificationNonce() []byte   // only needed for cryptoSetupServer
	SetDiversificationNonce([]byte) // only needed for cryptoSetupClient
	ConnectionState() ConnectionState

	GetSealer() (protocol.EncryptionLevel, Sealer)
	GetSealerWithEncryptionLevel(protocol.EncryptionLevel) (Sealer, error)
	GetSealerForCryptoStream() (protocol.EncryptionLevel, Sealer)
}

// ConnectionState records basic details about the QUIC connection.
// Warning: This API should not be considered stable and might change soon.
type ConnectionState struct {
	HandshakeComplete bool                // handshake is complete
	ServerName        string              // server name requested by client, if any (server side only)
	PeerCertificates  []*x509.Certificate // certificate chain presented by remote peer
}
