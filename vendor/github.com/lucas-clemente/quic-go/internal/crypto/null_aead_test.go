package crypto

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("NullAEAD", func() {
	It("selects the right FVN variant", func() {
		connID := protocol.ConnectionID([]byte{0x42, 0, 0, 0, 0, 0, 0, 0})
		Expect(NewNullAEAD(protocol.PerspectiveClient, connID, protocol.Version39)).To(Equal(&nullAEADFNV128a{
			perspective: protocol.PerspectiveClient,
		}))
		Expect(NewNullAEAD(protocol.PerspectiveClient, connID, protocol.VersionTLS)).To(BeAssignableToTypeOf(&aeadAESGCM{}))
	})
})
