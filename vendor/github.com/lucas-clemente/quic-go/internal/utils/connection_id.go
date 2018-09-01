package utils

import (
	"crypto/rand"
	"encoding/binary"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

// GenerateConnectionID generates a connection ID using cryptographic random
func GenerateConnectionID() (protocol.ConnectionID, error) {
	b := make([]byte, 8)
	_, err := rand.Read(b)
	if err != nil {
		return 0, err
	}
	return protocol.ConnectionID(binary.LittleEndian.Uint64(b)), nil
}
