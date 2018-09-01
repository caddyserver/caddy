package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

type aeadAESGCM struct {
	otherIV   []byte
	myIV      []byte
	encrypter cipher.AEAD
	decrypter cipher.AEAD
}

var _ AEAD = &aeadAESGCM{}

const ivLen = 12

// NewAEADAESGCM creates a AEAD using AES-GCM
func NewAEADAESGCM(otherKey []byte, myKey []byte, otherIV []byte, myIV []byte) (AEAD, error) {
	// the IVs need to be at least 8 bytes long, otherwise we can't compute the nonce
	if len(otherIV) != ivLen || len(myIV) != ivLen {
		return nil, errors.New("AES-GCM: expected 12 byte IVs")
	}

	encrypterCipher, err := aes.NewCipher(myKey)
	if err != nil {
		return nil, err
	}
	encrypter, err := cipher.NewGCM(encrypterCipher)
	if err != nil {
		return nil, err
	}
	decrypterCipher, err := aes.NewCipher(otherKey)
	if err != nil {
		return nil, err
	}
	decrypter, err := cipher.NewGCM(decrypterCipher)
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
	return aead.decrypter.Open(dst, aead.makeNonce(aead.otherIV, packetNumber), src, associatedData)
}

func (aead *aeadAESGCM) Seal(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) []byte {
	return aead.encrypter.Seal(dst, aead.makeNonce(aead.myIV, packetNumber), src, associatedData)
}

func (aead *aeadAESGCM) makeNonce(iv []byte, packetNumber protocol.PacketNumber) []byte {
	nonce := make([]byte, ivLen)
	binary.BigEndian.PutUint64(nonce[ivLen-8:], uint64(packetNumber))
	for i := 0; i < ivLen; i++ {
		nonce[i] ^= iv[i]
	}
	return nonce
}

func (aead *aeadAESGCM) Overhead() int {
	return aead.encrypter.Overhead()
}
