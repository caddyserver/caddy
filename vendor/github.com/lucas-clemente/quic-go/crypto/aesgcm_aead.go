package crypto

import (
	"crypto/cipher"
	"errors"

	"github.com/lucas-clemente/aes12"

	"github.com/lucas-clemente/quic-go/protocol"
)

type aeadAESGCM struct {
	otherIV   []byte
	myIV      []byte
	encrypter cipher.AEAD
	decrypter cipher.AEAD
}

// NewAEADAESGCM creates a AEAD using AES-GCM with 12 bytes tag size
//
// AES-GCM support is a bit hacky, since the go stdlib does not support 12 byte
// tag size, and couples the cipher and aes packages closely.
// See https://github.com/lucas-clemente/aes12.
func NewAEADAESGCM(otherKey []byte, myKey []byte, otherIV []byte, myIV []byte) (AEAD, error) {
	if len(myKey) != 16 || len(otherKey) != 16 || len(myIV) != 4 || len(otherIV) != 4 {
		return nil, errors.New("AES-GCM: expected 16-byte keys and 4-byte IVs")
	}
	encrypterCipher, err := aes12.NewCipher(myKey)
	if err != nil {
		return nil, err
	}
	encrypter, err := aes12.NewGCM(encrypterCipher)
	if err != nil {
		return nil, err
	}
	decrypterCipher, err := aes12.NewCipher(otherKey)
	if err != nil {
		return nil, err
	}
	decrypter, err := aes12.NewGCM(decrypterCipher)
	if err != nil {
		return nil, err
	}
	return &aeadAESGCM{
		otherIV:   otherIV,
		myIV:      myIV,
		encrypter: encrypter,
		decrypter: decrypter,
	}, nil
}

func (aead *aeadAESGCM) Open(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, error) {
	return aead.decrypter.Open(dst, makeNonce(aead.otherIV, packetNumber), src, associatedData)
}

func (aead *aeadAESGCM) Seal(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) []byte {
	return aead.encrypter.Seal(dst, makeNonce(aead.myIV, packetNumber), src, associatedData)
}
