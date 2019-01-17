package crypto

import (
	"github.com/bifurcation/mint"
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

const (
	clientExporterLabel = "EXPORTER-QUIC client 1rtt"
	serverExporterLabel = "EXPORTER-QUIC server 1rtt"
)

// A TLSExporter gets the negotiated ciphersuite and computes exporter
type TLSExporter interface {
	ConnectionState() mint.ConnectionState
	ComputeExporter(label string, context []byte, keyLength int) ([]byte, error)
}

// DeriveAESKeys derives the AES keys and creates a matching AES-GCM AEAD instance
func DeriveAESKeys(tls TLSExporter, pers protocol.Perspective) (AEAD, error) {
	var myLabel, otherLabel string
	if pers == protocol.PerspectiveClient {
		myLabel = clientExporterLabel
		otherLabel = serverExporterLabel
	} else {
		myLabel = serverExporterLabel
		otherLabel = clientExporterLabel
	}
	myKey, myIV, err := computeKeyAndIV(tls, myLabel)
	if err != nil {
		return nil, err
	}
	otherKey, otherIV, err := computeKeyAndIV(tls, otherLabel)
	if err != nil {
		return nil, err
	}
	return NewAEADAESGCM(otherKey, myKey, otherIV, myIV)
}

func computeKeyAndIV(tls TLSExporter, label string) (key, iv []byte, err error) {
	cs := tls.ConnectionState().CipherSuite
	secret, err := tls.ComputeExporter(label, nil, cs.Hash.Size())
	if err != nil {
		return nil, nil, err
	}
	key = qhkdfExpand(secret, "key", cs.KeyLen)
	iv = qhkdfExpand(secret, "iv", cs.IvLen)
	return key, iv, nil
}
