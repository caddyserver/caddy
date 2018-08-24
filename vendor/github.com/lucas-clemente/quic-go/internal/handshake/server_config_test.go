package handshake

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/crypto"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("ServerConfig", func() {
	var (
		kex crypto.KeyExchange
	)

	BeforeEach(func() {
		var err error
		kex, err = crypto.NewCurve25519KEX()
		Expect(err).NotTo(HaveOccurred())
	})

	It("generates a random ID and OBIT", func() {
		scfg1, err := NewServerConfig(kex, nil)
		Expect(err).ToNot(HaveOccurred())
		scfg2, err := NewServerConfig(kex, nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(scfg1.ID).ToNot(Equal(scfg2.ID))
		Expect(scfg1.obit).ToNot(Equal(scfg2.obit))
		Expect(scfg1.cookieGenerator).ToNot(Equal(scfg2.cookieGenerator))
	})

	It("gets the proper binary representation", func() {
		scfg, err := NewServerConfig(kex, nil)
		Expect(err).NotTo(HaveOccurred())
		expected := bytes.NewBuffer([]byte{0x53, 0x43, 0x46, 0x47, 0x6, 0x0, 0x0, 0x0, 0x41, 0x45, 0x41, 0x44, 0x4, 0x0, 0x0, 0x0, 0x53, 0x43, 0x49, 0x44, 0x14, 0x0, 0x0, 0x0, 0x50, 0x55, 0x42, 0x53, 0x37, 0x0, 0x0, 0x0, 0x4b, 0x45, 0x58, 0x53, 0x3b, 0x0, 0x0, 0x0, 0x4f, 0x42, 0x49, 0x54, 0x43, 0x0, 0x0, 0x0, 0x45, 0x58, 0x50, 0x59, 0x4b, 0x0, 0x0, 0x0, 0x41, 0x45, 0x53, 0x47})
		expected.Write(scfg.ID)
		expected.Write([]byte{0x20, 0x0, 0x0})
		expected.Write(kex.PublicKey())
		expected.Write([]byte{0x43, 0x32, 0x35, 0x35})
		expected.Write(scfg.obit)
		expected.Write([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
		Expect(scfg.Get()).To(Equal(expected.Bytes()))
	})
})
