package crypto

import (
	"crypto"
	"errors"

	"github.com/bifurcation/mint"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockTLSExporter struct {
	hash          crypto.Hash
	computerError error
}

var _ TLSExporter = &mockTLSExporter{}

func (c *mockTLSExporter) Handshake() mint.Alert { panic("not implemented") }

func (c *mockTLSExporter) ConnectionState() mint.ConnectionState {
	return mint.ConnectionState{
		CipherSuite: mint.CipherSuiteParams{
			Hash:   c.hash,
			KeyLen: 32,
			IvLen:  12,
		},
	}
}

func (c *mockTLSExporter) ComputeExporter(label string, context []byte, keyLength int) ([]byte, error) {
	if c.computerError != nil {
		return nil, c.computerError
	}
	return append([]byte(label), context...), nil
}

var _ = Describe("Key Derivation", func() {
	It("derives keys", func() {
		clientAEAD, err := DeriveAESKeys(&mockTLSExporter{hash: crypto.SHA256}, protocol.PerspectiveClient)
		Expect(err).ToNot(HaveOccurred())
		serverAEAD, err := DeriveAESKeys(&mockTLSExporter{hash: crypto.SHA256}, protocol.PerspectiveServer)
		Expect(err).ToNot(HaveOccurred())
		ciphertext := clientAEAD.Seal(nil, []byte("foobar"), 0, []byte("aad"))
		data, err := serverAEAD.Open(nil, ciphertext, 0, []byte("aad"))
		Expect(err).ToNot(HaveOccurred())
		Expect(data).To(Equal([]byte("foobar")))
	})

	It("fails when computing the exporter fails", func() {
		testErr := errors.New("test error")
		_, err := DeriveAESKeys(&mockTLSExporter{hash: crypto.SHA256, computerError: testErr}, protocol.PerspectiveClient)
		Expect(err).To(MatchError(testErr))
	})
})
