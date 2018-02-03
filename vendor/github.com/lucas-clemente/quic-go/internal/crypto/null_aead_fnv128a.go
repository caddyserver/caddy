package crypto

import (
	"encoding/binary"
	"errors"

	"github.com/lucas-clemente/fnv128a"
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

// nullAEAD handles not-yet encrypted packets
type nullAEADFNV128a struct {
	perspective protocol.Perspective
}

var _ AEAD = &nullAEADFNV128a{}

// Open and verify the ciphertext
func (n *nullAEADFNV128a) Open(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, error) {
	if len(src) < 12 {
		return nil, errors.New("NullAEAD: ciphertext cannot be less than 12 bytes long")
	}

	hash := fnv128a.New()
	hash.Write(associatedData)
	hash.Write(src[12:])
	if n.perspective == protocol.PerspectiveServer {
		hash.Write([]byte("Client"))
	} else {
		hash.Write([]byte("Server"))
	}
	testHigh, testLow := hash.Sum128()

	low := binary.LittleEndian.Uint64(src)
	high := binary.LittleEndian.Uint32(src[8:])

	if uint32(testHigh&0xffffffff) != high || testLow != low {
		return nil, errors.New("NullAEAD: failed to authenticate received data")
	}
	return src[12:], nil
}

// Seal writes hash and ciphertext to the buffer
func (n *nullAEADFNV128a) Seal(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) []byte {
	if cap(dst) < 12+len(src) {
		dst = make([]byte, 12+len(src))
	} else {
		dst = dst[:12+len(src)]
	}

	hash := fnv128a.New()
	hash.Write(associatedData)
	hash.Write(src)

	if n.perspective == protocol.PerspectiveServer {
		hash.Write([]byte("Server"))
	} else {
		hash.Write([]byte("Client"))
	}

	high, low := hash.Sum128()

	copy(dst[12:], src)
	binary.LittleEndian.PutUint64(dst, low)
	binary.LittleEndian.PutUint32(dst[8:], uint32(high))
	return dst
}

func (n *nullAEADFNV128a) Overhead() int {
	return 12
}
