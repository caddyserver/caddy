package crypto

import (
	"bytes"
	"crypto/sha256"
	"io"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"

	"golang.org/x/crypto/hkdf"
)

// DeriveKeysChacha20 derives the client and server keys and creates a matching chacha20poly1305 AEAD instance
// func DeriveKeysChacha20(version protocol.VersionNumber, forwardSecure bool, sharedSecret, nonces []byte, connID protocol.ConnectionID, chlo []byte, scfg []byte, cert []byte, divNonce []byte) (AEAD, error) {
// 	otherKey, myKey, otherIV, myIV, err := deriveKeys(version, forwardSecure, sharedSecret, nonces, connID, chlo, scfg, cert, divNonce, 32)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return NewAEADChacha20Poly1305(otherKey, myKey, otherIV, myIV)
// }

// DeriveQuicCryptoAESKeys derives the client and server keys and creates a matching AES-GCM AEAD instance
func DeriveQuicCryptoAESKeys(forwardSecure bool, sharedSecret, nonces []byte, connID protocol.ConnectionID, chlo []byte, scfg []byte, cert []byte, divNonce []byte, pers protocol.Perspective) (AEAD, error) {
	var swap bool
	if pers == protocol.PerspectiveClient {
		swap = true
	}
	otherKey, myKey, otherIV, myIV, err := deriveKeys(forwardSecure, sharedSecret, nonces, connID, chlo, scfg, cert, divNonce, 16, swap)
	if err != nil {
		return nil, err
	}
	return NewAEADAESGCM12(otherKey, myKey, otherIV, myIV)
}

// deriveKeys derives the keys and the IVs
// swap should be set true if generating the values for the client, and false for the server
func deriveKeys(forwardSecure bool, sharedSecret, nonces []byte, connID protocol.ConnectionID, chlo, scfg, cert, divNonce []byte, keyLen int, swap bool) ([]byte, []byte, []byte, []byte, error) {
	var info bytes.Buffer
	if forwardSecure {
		info.Write([]byte("QUIC forward secure key expansion\x00"))
	} else {
		info.Write([]byte("QUIC key expansion\x00"))
	}
	utils.BigEndian.WriteUint64(&info, uint64(connID))
	info.Write(chlo)
	info.Write(scfg)
	info.Write(cert)

	r := hkdf.New(sha256.New, sharedSecret, nonces, info.Bytes())

	s := make([]byte, 2*keyLen+2*4)
	if _, err := io.ReadFull(r, s); err != nil {
		return nil, nil, nil, nil, err
	}

	key1 := s[:keyLen]
	key2 := s[keyLen : 2*keyLen]
	iv1 := s[2*keyLen : 2*keyLen+4]
	iv2 := s[2*keyLen+4:]

	var otherKey, myKey []byte
	var otherIV, myIV []byte

	if !forwardSecure {
		if err := diversify(key2, iv2, divNonce); err != nil {
			return nil, nil, nil, nil, err
		}
	}

	if swap {
		otherKey = key2
		myKey = key1
		otherIV = iv2
		myIV = iv1
	} else {
		otherKey = key1
		myKey = key2
		otherIV = iv1
		myIV = iv2
	}

	return otherKey, myKey, otherIV, myIV, nil
}

func diversify(key, iv, divNonce []byte) error {
	secret := make([]byte, len(key)+len(iv))
	copy(secret, key)
	copy(secret[len(key):], iv)

	r := hkdf.New(sha256.New, secret, divNonce, []byte("QUIC key diversification"))

	if _, err := io.ReadFull(r, key); err != nil {
		return err
	}
	if _, err := io.ReadFull(r, iv); err != nil {
		return err
	}

	return nil
}
