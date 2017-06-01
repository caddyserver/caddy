// +build ignore

package crypto

import (
	"crypto/cipher"
	"errors"

	"github.com/aead/chacha20"

	"github.com/lucas-clemente/quic-go/protocol"
)

type aeadChacha20Poly1305 struct {
	otherIV   []byte
	myIV      []byte
	encrypter cipher.AEAD
	decrypter cipher.AEAD
}

// NewAEADChacha20Poly1305 creates a AEAD using chacha20poly1305
func NewAEADChacha20Poly1305(otherKey []byte, myKey []byte, otherIV []byte, myIV []byte) (AEAD, error) {
	if len(myKey) != 32 || len(otherKey) != 32 || len(myIV) != 4 || len(otherIV) != 4 {
		return nil, errors.New("chacha20poly1305: expected 32-byte keys and 4-byte IVs")
	}
	// copy because ChaCha20Poly1305 expects array pointers
	var MyKey, OtherKey [32]byte
	copy(MyKey[:], myKey)
	copy(OtherKey[:], otherKey)

	encrypter, err := chacha20.NewChaCha20Poly1305WithTagSize(&MyKey, 12)
	if err != nil {
		return nil, err
	}
	decrypter, err := chacha20.NewChaCha20Poly1305WithTagSize(&OtherKey, 12)
	if err != nil {
		return nil, err
	}
	return &aeadChacha20Poly1305{
		otherIV:   otherIV,
		myIV:      myIV,
		encrypter: encrypter,
		decrypter: decrypter,
	}, nil
}

func (aead *aeadChacha20Poly1305) Open(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, error) {
	return aead.decrypter.Open(dst, makeNonce(aead.otherIV, packetNumber), src, associatedData)
}

func (aead *aeadChacha20Poly1305) Seal(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) []byte {
	return aead.encrypter.Seal(dst, makeNonce(aead.myIV, packetNumber), src, associatedData)
}
