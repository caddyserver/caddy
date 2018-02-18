package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
)

type ecdsaSignature struct {
	R, S *big.Int
}

// signServerProof signs CHLO and server config for use in the server proof
func signServerProof(cert *tls.Certificate, chlo []byte, serverConfigData []byte) ([]byte, error) {
	hash := sha256.New()
	hash.Write([]byte("QUIC CHLO and server config signature\x00"))
	chloHash := sha256.Sum256(chlo)
	hash.Write([]byte{32, 0, 0, 0})
	hash.Write(chloHash[:])
	hash.Write(serverConfigData)

	key, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("expected PrivateKey to implement crypto.Signer")
	}

	opts := crypto.SignerOpts(crypto.SHA256)

	if _, ok = key.(*rsa.PrivateKey); ok {
		opts = &rsa.PSSOptions{SaltLength: 32, Hash: crypto.SHA256}
	}

	return key.Sign(rand.Reader, hash.Sum(nil), opts)
}

// verifyServerProof verifies the server proof signature
func verifyServerProof(proof []byte, cert *x509.Certificate, chlo []byte, serverConfigData []byte) bool {
	hash := sha256.New()
	hash.Write([]byte("QUIC CHLO and server config signature\x00"))
	chloHash := sha256.Sum256(chlo)
	hash.Write([]byte{32, 0, 0, 0})
	hash.Write(chloHash[:])
	hash.Write(serverConfigData)

	// RSA
	if cert.PublicKeyAlgorithm == x509.RSA {
		opts := &rsa.PSSOptions{SaltLength: 32, Hash: crypto.SHA256}
		err := rsa.VerifyPSS(cert.PublicKey.(*rsa.PublicKey), crypto.SHA256, hash.Sum(nil), proof, opts)
		return err == nil
	}

	// ECDSA
	signature := &ecdsaSignature{}
	rest, err := asn1.Unmarshal(proof, signature)
	if err != nil || len(rest) != 0 {
		return false
	}
	return ecdsa.Verify(cert.PublicKey.(*ecdsa.PublicKey), hash.Sum(nil), signature.R, signature.S)
}
