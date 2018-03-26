package handshake

import (
	"bytes"
	"crypto/rand"

	"github.com/lucas-clemente/quic-go/internal/crypto"
)

// ServerConfig is a server config
type ServerConfig struct {
	kex             crypto.KeyExchange
	certChain       crypto.CertChain
	ID              []byte
	obit            []byte
	cookieGenerator *CookieGenerator
}

// NewServerConfig creates a new server config
func NewServerConfig(kex crypto.KeyExchange, certChain crypto.CertChain) (*ServerConfig, error) {
	id := make([]byte, 16)
	_, err := rand.Read(id)
	if err != nil {
		return nil, err
	}

	obit := make([]byte, 8)
	if _, err = rand.Read(obit); err != nil {
		return nil, err
	}

	cookieGenerator, err := NewCookieGenerator()

	if err != nil {
		return nil, err
	}

	return &ServerConfig{
		kex:             kex,
		certChain:       certChain,
		ID:              id,
		obit:            obit,
		cookieGenerator: cookieGenerator,
	}, nil
}

// Get the server config binary representation
func (s *ServerConfig) Get() []byte {
	var serverConfig bytes.Buffer
	msg := HandshakeMessage{
		Tag: TagSCFG,
		Data: map[Tag][]byte{
			TagSCID: s.ID,
			TagKEXS: []byte("C255"),
			TagAEAD: []byte("AESG"),
			TagPUBS: append([]byte{0x20, 0x00, 0x00}, s.kex.PublicKey()...),
			TagOBIT: s.obit,
			TagEXPY: {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		},
	}
	msg.Write(&serverConfig)
	return serverConfig.Bytes()
}

// Sign the server config and CHLO with the server's keyData
func (s *ServerConfig) Sign(sni string, chlo []byte) ([]byte, error) {
	return s.certChain.SignServerProof(sni, chlo, s.Get())
}

// GetCertsCompressed returns the certificate data
func (s *ServerConfig) GetCertsCompressed(sni string, commonSetHashes, compressedHashes []byte) ([]byte, error) {
	return s.certChain.GetCertsCompressed(sni, commonSetHashes, compressedHashes)
}
