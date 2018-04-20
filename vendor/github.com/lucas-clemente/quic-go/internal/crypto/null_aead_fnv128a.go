package crypto

import (
	"bytes"
	"errors"
	"fmt"
	"hash/fnv"

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

	hash := fnv.New128a()
	hash.Write(associatedData)
	hash.Write(src[12:])
	if n.perspective == protocol.PerspectiveServer {
		hash.Write([]byte("Client"))
	} else {
		hash.Write([]byte("Server"))
	}
	sum := make([]byte, 0, 16)
	sum = hash.Sum(sum)
	// The tag is written in little endian, so we need to reverse the slice.
	reverse(sum)

	if !bytes.Equal(sum[:12], src[:12]) {
		return nil, fmt.Errorf("NullAEAD: failed to authenticate received data (%#v vs %#v)", sum[:12], src[:12])
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

	hash := fnv.New128a()
	hash.Write(associatedData)
	hash.Write(src)

	if n.perspective == protocol.PerspectiveServer {
		hash.Write([]byte("Server"))
	} else {
		hash.Write([]byte("Client"))
	}
	sum := make([]byte, 0, 16)
	sum = hash.Sum(sum)
	// The tag is written in little endian, so we need to reverse the slice.
	reverse(sum)

	copy(dst[12:], src)
	copy(dst, sum[:12])
	return dst
}

func (n *nullAEADFNV128a) Overhead() int {
	return 12
}

func reverse(a []byte) {
	for left, right := 0, len(a)-1; left < right; left, right = left+1, right-1 {
		a[left], a[right] = a[right], a[left]
	}
}
