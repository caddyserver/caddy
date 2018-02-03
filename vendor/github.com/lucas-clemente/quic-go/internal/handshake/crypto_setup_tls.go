package handshake

import (
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/bifurcation/mint"
	"github.com/lucas-clemente/quic-go/internal/crypto"
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

// ErrCloseSessionForRetry is returned by HandleCryptoStream when the server wishes to perform a stateless retry
var ErrCloseSessionForRetry = errors.New("closing session in order to recreate after a retry")

// KeyDerivationFunction is used for key derivation
type KeyDerivationFunction func(crypto.TLSExporter, protocol.Perspective) (crypto.AEAD, error)

type cryptoSetupTLS struct {
	mutex sync.RWMutex

	perspective protocol.Perspective

	keyDerivation KeyDerivationFunction
	nullAEAD      crypto.AEAD
	aead          crypto.AEAD

	tls            MintTLS
	cryptoStream   *CryptoStreamConn
	handshakeEvent chan<- struct{}
}

// NewCryptoSetupTLSServer creates a new TLS CryptoSetup instance for a server
func NewCryptoSetupTLSServer(
	tls MintTLS,
	cryptoStream *CryptoStreamConn,
	nullAEAD crypto.AEAD,
	handshakeEvent chan<- struct{},
	version protocol.VersionNumber,
) CryptoSetup {
	return &cryptoSetupTLS{
		tls:            tls,
		cryptoStream:   cryptoStream,
		nullAEAD:       nullAEAD,
		perspective:    protocol.PerspectiveServer,
		keyDerivation:  crypto.DeriveAESKeys,
		handshakeEvent: handshakeEvent,
	}
}

// NewCryptoSetupTLSClient creates a new TLS CryptoSetup instance for a client
func NewCryptoSetupTLSClient(
	cryptoStream io.ReadWriter,
	connID protocol.ConnectionID,
	hostname string,
	handshakeEvent chan<- struct{},
	tls MintTLS,
	version protocol.VersionNumber,
) (CryptoSetup, error) {
	nullAEAD, err := crypto.NewNullAEAD(protocol.PerspectiveClient, connID, version)
	if err != nil {
		return nil, err
	}

	return &cryptoSetupTLS{
		perspective:    protocol.PerspectiveClient,
		tls:            tls,
		nullAEAD:       nullAEAD,
		keyDerivation:  crypto.DeriveAESKeys,
		handshakeEvent: handshakeEvent,
	}, nil
}

func (h *cryptoSetupTLS) HandleCryptoStream() error {
	if h.perspective == protocol.PerspectiveServer {
		// mint already wrote the ServerHello, EncryptedExtensions and the certificate chain to the buffer
		// send out that data now
		if _, err := h.cryptoStream.Flush(); err != nil {
			return err
		}
	}

handshakeLoop:
	for {
		if alert := h.tls.Handshake(); alert != mint.AlertNoAlert {
			return fmt.Errorf("TLS handshake error: %s (Alert %d)", alert.String(), alert)
		}
		switch h.tls.State() {
		case mint.StateClientStart: // this happens if a stateless retry is performed
			return ErrCloseSessionForRetry
		case mint.StateClientConnected, mint.StateServerConnected:
			break handshakeLoop
		}
	}

	aead, err := h.keyDerivation(h.tls, h.perspective)
	if err != nil {
		return err
	}
	h.mutex.Lock()
	h.aead = aead
	h.mutex.Unlock()

	h.handshakeEvent <- struct{}{}
	close(h.handshakeEvent)
	return nil
}

func (h *cryptoSetupTLS) Open(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, protocol.EncryptionLevel, error) {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	if h.aead != nil {
		data, err := h.aead.Open(dst, src, packetNumber, associatedData)
		if err != nil {
			return nil, protocol.EncryptionUnspecified, err
		}
		return data, protocol.EncryptionForwardSecure, nil
	}
	data, err := h.nullAEAD.Open(dst, src, packetNumber, associatedData)
	if err != nil {
		return nil, protocol.EncryptionUnspecified, err
	}
	return data, protocol.EncryptionUnencrypted, nil
}

func (h *cryptoSetupTLS) GetSealer() (protocol.EncryptionLevel, Sealer) {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	if h.aead != nil {
		return protocol.EncryptionForwardSecure, h.aead
	}
	return protocol.EncryptionUnencrypted, h.nullAEAD
}

func (h *cryptoSetupTLS) GetSealerWithEncryptionLevel(encLevel protocol.EncryptionLevel) (Sealer, error) {
	errNoSealer := fmt.Errorf("CryptoSetup: no sealer with encryption level %s", encLevel.String())
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	switch encLevel {
	case protocol.EncryptionUnencrypted:
		return h.nullAEAD, nil
	case protocol.EncryptionForwardSecure:
		if h.aead == nil {
			return nil, errNoSealer
		}
		return h.aead, nil
	default:
		return nil, errNoSealer
	}
}

func (h *cryptoSetupTLS) GetSealerForCryptoStream() (protocol.EncryptionLevel, Sealer) {
	return protocol.EncryptionUnencrypted, h.nullAEAD
}

func (h *cryptoSetupTLS) DiversificationNonce() []byte {
	panic("diversification nonce not needed for TLS")
}

func (h *cryptoSetupTLS) SetDiversificationNonce([]byte) {
	panic("diversification nonce not needed for TLS")
}

func (h *cryptoSetupTLS) ConnectionState() ConnectionState {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	mintConnState := h.tls.ConnectionState()
	return ConnectionState{
		// TODO: set the ServerName, once mint exports it
		HandshakeComplete: h.aead != nil,
		PeerCertificates:  mintConnState.PeerCertificates,
	}
}
