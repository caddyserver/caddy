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

type baseCryptoSetup interface {
	HandleCryptoStream() error
	ConnectionState() ConnectionState

	GetSealer() (protocol.EncryptionLevel, Sealer)
	GetSealerWithEncryptionLevel(protocol.EncryptionLevel) (Sealer, error)
	GetSealerForCryptoStream() (protocol.EncryptionLevel, Sealer)
}

// CryptoSetup is the crypto setup used by gQUIC
type CryptoSetup interface {
	baseCryptoSetup

	Open(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, protocol.EncryptionLevel, error)
}

// CryptoSetupTLS is the crypto setup used by IETF QUIC
type CryptoSetupTLS interface {
	baseCryptoSetup

	OpenHandshake(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, error)
	Open1RTT(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, error)
}

// ConnectionState records basic details about the QUIC connection.
// Warning: This API should not be considered stable and might change soon.
type ConnectionState struct {
	HandshakeComplete bool                // handshake is complete
	ServerName        string              // server name requested by client, if any (server side only)
	PeerCertificates  []*x509.Certificate // certificate chain presented by remote peer
}
