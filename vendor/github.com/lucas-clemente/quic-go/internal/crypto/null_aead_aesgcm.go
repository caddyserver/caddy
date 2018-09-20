package crypto

import (
	"crypto"

	"github.com/bifurcation/mint"
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

var quicVersion1Salt = []byte{0x9c, 0x10, 0x8f, 0x98, 0x52, 0x0a, 0x5c, 0x5c, 0x32, 0x96, 0x8e, 0x95, 0x0e, 0x8a, 0x2c, 0x5f, 0xe0, 0x6d, 0x6c, 0x38}

func newNullAEADAESGCM(connectionID protocol.ConnectionID, pers protocol.Perspective) (AEAD, error) {
	clientSecret, serverSecret := computeSecrets(connectionID)

	var mySecret, otherSecret []byte
	if pers == protocol.PerspectiveClient {
		mySecret = clientSecret
		otherSecret = serverSecret
	} else {
		mySecret = serverSecret
		otherSecret = clientSecret
	}

	myKey, myIV := computeNullAEADKeyAndIV(mySecret)
	otherKey, otherIV := computeNullAEADKeyAndIV(otherSecret)

	return NewAEADAESGCM(otherKey, myKey, otherIV, myIV)
}

func computeSecrets(connID protocol.ConnectionID) (clientSecret, serverSecret []byte) {
	handshakeSecret := mint.HkdfExtract(crypto.SHA256, quicVersion1Salt, connID)
	clientSecret = qhkdfExpand(handshakeSecret, "client hs", crypto.SHA256.Size())
	serverSecret = qhkdfExpand(handshakeSecret, "server hs", crypto.SHA256.Size())
	return
}

func computeNullAEADKeyAndIV(secret []byte) (key, iv []byte) {
	key = qhkdfExpand(secret, "key", 16)
	iv = qhkdfExpand(secret, "iv", 12)
	return
}
