package crypto

import (
	lru "github.com/hashicorp/golang-lru"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Certificate cache", func() {
	BeforeEach(func() {
		var err error
		compressedCertsCache, err = lru.New(2)
		Expect(err).NotTo(HaveOccurred())
	})

	It("gives a compressed cert", func() {
		chain := [][]byte{{0xde, 0xca, 0xfb, 0xad}}
		expected, err := compressChain(chain, nil, nil)
		Expect(err).NotTo(HaveOccurred())
		compressed, err := getCompressedCert(chain, nil, nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(compressed).To(Equal(expected))
	})

	It("gets the same result multiple times", func() {
		chain := [][]byte{{0xde, 0xca, 0xfb, 0xad}}
		compressed, err := getCompressedCert(chain, nil, nil)
		Expect(err).NotTo(HaveOccurred())
		compressed2, err := getCompressedCert(chain, nil, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(compressed).To(Equal(compressed2))
	})

	It("stores cached values", func() {
		chain := [][]byte{{0xde, 0xca, 0xfb, 0xad}}
		_, err := getCompressedCert(chain, nil, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(compressedCertsCache.Len()).To(Equal(1))
		Expect(compressedCertsCache.Contains(uint64(3838929964809501833))).To(BeTrue())
	})

	It("evicts old values", func() {
		_, err := getCompressedCert([][]byte{{0x00}}, nil, nil)
		Expect(err).NotTo(HaveOccurred())
		_, err = getCompressedCert([][]byte{{0x01}}, nil, nil)
		Expect(err).NotTo(HaveOccurred())
		_, err = getCompressedCert([][]byte{{0x02}}, nil, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(compressedCertsCache.Len()).To(Equal(2))
	})
})
