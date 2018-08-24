package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestWire(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Wire Suite")
}

const (
	// a QUIC version that uses big endian encoding
	versionBigEndian = protocol.Version39
	// a QUIC version that uses the IETF frame types
	versionIETFFrames = protocol.VersionTLS
	// a QUIC version that uses the gQUIC Public Header
	versionPublicHeader = protocol.Version43
	// a QUIC version that the IETF QUIC Header
	versionIETFHeader = protocol.VersionTLS
)

func encodeVarInt(i uint64) []byte {
	b := &bytes.Buffer{}
	utils.WriteVarInt(b, i)
	return b.Bytes()
}

var _ = BeforeSuite(func() {
	Expect(versionBigEndian.UsesIETFFrameFormat()).To(BeFalse())
	Expect(versionIETFFrames.UsesIETFFrameFormat()).To(BeTrue())
})
