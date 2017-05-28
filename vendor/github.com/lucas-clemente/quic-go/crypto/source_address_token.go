package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// StkSource is used to create and verify source address tokens
type StkSource interface {
	// NewToken creates a new token
	NewToken([]byte) ([]byte, error)
	// DecodeToken decodes a token
	DecodeToken([]byte) ([]byte, error)
}

type stkSource struct {
	aead cipher.AEAD
}

const stkKeySize = 16

// Chrome currently sets this to 12, but discusses changing it to 16. We start
// at 16 :)
const stkNonceSize = 16

// NewStkSource creates a source for source address tokens
func NewStkSource() (StkSource, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	key, err := deriveKey(secret)
	if err != nil {
		return nil, err
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithNonceSize(c, stkNonceSize)
	if err != nil {
		return nil, err
	}
	return &stkSource{aead: aead}, nil
}

func (s *stkSource) NewToken(data []byte) ([]byte, error) {
	nonce := make([]byte, stkNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return s.aead.Seal(nonce, nonce, data, nil), nil
}

func (s *stkSource) DecodeToken(p []byte) ([]byte, error) {
	if len(p) < stkNonceSize {
		return nil, fmt.Errorf("STK too short: %d", len(p))
	}
	nonce := p[:stkNonceSize]
	return s.aead.Open(nil, nonce, p[stkNonceSize:], nil)
}

func deriveKey(secret []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, secret, nil, []byte("QUIC source address token key"))
	key := make([]byte, stkKeySize)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}
