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

// KeyDerivationFunction is used for key derivation
type KeyDerivationFunction func(crypto.TLSExporter, protocol.Perspective) (crypto.AEAD, error)

type cryptoSetupTLS struct {
	mutex sync.RWMutex

	perspective protocol.Perspective

	keyDerivation KeyDerivationFunction
	nullAEAD      crypto.AEAD
	aead          crypto.AEAD

	tls            mintTLS
	conn           *cryptoStreamConn
	handshakeEvent chan<- struct{}
}

var _ CryptoSetupTLS = &cryptoSetupTLS{}

// NewCryptoSetupTLSServer creates a new TLS CryptoSetup instance for a server
func NewCryptoSetupTLSServer(
	cryptoStream io.ReadWriter,
	connID protocol.ConnectionID,
	config *mint.Config,
	handshakeEvent chan<- struct{},
	version protocol.VersionNumber,
) (CryptoSetupTLS, error) {
	nullAEAD, err := crypto.NewNullAEAD(protocol.PerspectiveServer, connID, version)
	if err != nil {
		return nil, err
	}
	conn := newCryptoStreamConn(cryptoStream)
	tls := mint.Server(conn, config)
	return &cryptoSetupTLS{
		tls:            tls,
		conn:           conn,
		nullAEAD:       nullAEAD,
		perspective:    protocol.PerspectiveServer,
		keyDerivation:  crypto.DeriveAESKeys,
		handshakeEvent: handshakeEvent,
	}, nil
}

// NewCryptoSetupTLSClient creates a new TLS CryptoSetup instance for a client
func NewCryptoSetupTLSClient(
	cryptoStream io.ReadWriter,
	connID protocol.ConnectionID,
	config *mint.Config,
	handshakeEvent chan<- struct{},
	version protocol.VersionNumber,
) (CryptoSetupTLS, error) {
	nullAEAD, err := crypto.NewNullAEAD(protocol.PerspectiveClient, connID, version)
	if err != nil {
		return nil, err
	}
	conn := newCryptoStreamConn(cryptoStream)
	tls := mint.Client(conn, config)
	return &cryptoSetupTLS{
		tls:            tls,
		conn:           conn,
		perspective:    protocol.PerspectiveClient,
		nullAEAD:       nullAEAD,
		keyDerivation:  crypto.DeriveAESKeys,
		handshakeEvent: handshakeEvent,
	}, nil
}

func (h *cryptoSetupTLS) HandleCryptoStream() error {
	for {
		if alert := h.tls.Handshake(); alert != mint.AlertNoAlert {
			return fmt.Errorf("TLS handshake error: %s (Alert %d)", alert.String(), alert)
		}
		state := h.tls.ConnectionState().HandshakeState
		if err := h.conn.Flush(); err != nil {
			return err
		}
		if state == mint.StateClientConnected || state == mint.StateServerConnected {
			break
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

func (h *cryptoSetupTLS) OpenHandshake(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, error) {
	return h.nullAEAD.Open(dst, src, packetNumber, associatedData)
}

func (h *cryptoSetupTLS) Open1RTT(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, error) {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	if h.aead == nil {
		return nil, errors.New("no 1-RTT sealer")
	}
	return h.aead.Open(dst, src, packetNumber, associatedData)
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
