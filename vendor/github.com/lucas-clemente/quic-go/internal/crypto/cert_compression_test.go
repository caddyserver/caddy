package crypto

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"hash/fnv"

	"github.com/lucas-clemente/quic-go-certificates"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func byteHash(d []byte) []byte {
	h := fnv.New64a()
	h.Write(d)
	s := h.Sum64()
	res := make([]byte, 8)
	binary.LittleEndian.PutUint64(res, s)
	return res
}

var _ = Describe("Cert compression and decompression", func() {
	var certSetsOld map[uint64]certSet

	BeforeEach(func() {
		certSetsOld = make(map[uint64]certSet)
		for s := range certSets {
			certSetsOld[s] = certSets[s]
		}
	})

	AfterEach(func() {
		certSets = certSetsOld
	})

	It("compresses empty", func() {
		compressed, err := compressChain(nil, nil, nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(compressed).To(Equal([]byte{0}))
	})

	It("decompresses empty", func() {
		compressed, err := compressChain(nil, nil, nil)
		Expect(err).ToNot(HaveOccurred())
		uncompressed, err := decompressChain(compressed)
		Expect(err).ToNot(HaveOccurred())
		Expect(uncompressed).To(BeEmpty())
	})

	It("gives correct single cert", func() {
		cert := []byte{0xde, 0xca, 0xfb, 0xad}
		certZlib := &bytes.Buffer{}
		z, err := zlib.NewWriterLevelDict(certZlib, flate.BestCompression, certDictZlib)
		Expect(err).ToNot(HaveOccurred())
		z.Write([]byte{0x04, 0x00, 0x00, 0x00})
		z.Write(cert)
		z.Close()
		chain := [][]byte{cert}
		compressed, err := compressChain(chain, nil, nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(compressed).To(Equal(append([]byte{
			0x01, 0x00,
			0x08, 0x00, 0x00, 0x00,
		}, certZlib.Bytes()...)))
	})

	It("decompresses a single cert", func() {
		cert := []byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe}
		chain := [][]byte{cert}
		compressed, err := compressChain(chain, nil, nil)
		Expect(err).ToNot(HaveOccurred())
		uncompressed, err := decompressChain(compressed)
		Expect(err).ToNot(HaveOccurred())
		Expect(uncompressed).To(Equal(chain))
	})

	It("gives correct cert and intermediate", func() {
		cert1 := []byte{0xde, 0xca, 0xfb, 0xad}
		cert2 := []byte{0xde, 0xad, 0xbe, 0xef}
		certZlib := &bytes.Buffer{}
		z, err := zlib.NewWriterLevelDict(certZlib, flate.BestCompression, certDictZlib)
		Expect(err).ToNot(HaveOccurred())
		z.Write([]byte{0x04, 0x00, 0x00, 0x00})
		z.Write(cert1)
		z.Write([]byte{0x04, 0x00, 0x00, 0x00})
		z.Write(cert2)
		z.Close()
		chain := [][]byte{cert1, cert2}
		compressed, err := compressChain(chain, nil, nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(compressed).To(Equal(append([]byte{
			0x01, 0x01, 0x00,
			0x10, 0x00, 0x00, 0x00,
		}, certZlib.Bytes()...)))
	})

	It("decompresses the chain with a cert and an intermediate", func() {
		cert1 := []byte{0xde, 0xca, 0xfb, 0xad}
		cert2 := []byte{0xde, 0xad, 0xbe, 0xef}
		chain := [][]byte{cert1, cert2}
		compressed, err := compressChain(chain, nil, nil)
		Expect(err).ToNot(HaveOccurred())
		decompressed, err := decompressChain(compressed)
		Expect(err).ToNot(HaveOccurred())
		Expect(decompressed).To(Equal(chain))
	})

	It("uses cached certificates", func() {
		cert := []byte{0xde, 0xca, 0xfb, 0xad}
		certHash := byteHash(cert)
		chain := [][]byte{cert}
		compressed, err := compressChain(chain, nil, certHash)
		Expect(err).ToNot(HaveOccurred())
		expected := append([]byte{0x02}, certHash...)
		expected = append(expected, 0x00)
		Expect(compressed).To(Equal(expected))
	})

	It("uses cached certificates and compressed combined", func() {
		cert1 := []byte{0xde, 0xca, 0xfb, 0xad}
		cert2 := []byte{0xde, 0xad, 0xbe, 0xef}
		cert2Hash := byteHash(cert2)
		certZlib := &bytes.Buffer{}
		z, err := zlib.NewWriterLevelDict(certZlib, flate.BestCompression, append(cert2, certDictZlib...))
		Expect(err).ToNot(HaveOccurred())
		z.Write([]byte{0x04, 0x00, 0x00, 0x00})
		z.Write(cert1)
		z.Close()
		chain := [][]byte{cert1, cert2}
		compressed, err := compressChain(chain, nil, cert2Hash)
		Expect(err).ToNot(HaveOccurred())
		expected := []byte{0x01, 0x02}
		expected = append(expected, cert2Hash...)
		expected = append(expected, 0x00)
		expected = append(expected, []byte{0x08, 0, 0, 0}...)
		expected = append(expected, certZlib.Bytes()...)
		Expect(compressed).To(Equal(expected))
	})

	It("uses common certificate sets", func() {
		cert := certsets.CertSet3[42]
		setHash := make([]byte, 8)
		binary.LittleEndian.PutUint64(setHash, certsets.CertSet3Hash)
		chain := [][]byte{cert}
		compressed, err := compressChain(chain, setHash, nil)
		Expect(err).ToNot(HaveOccurred())
		expected := []byte{0x03}
		expected = append(expected, setHash...)
		expected = append(expected, []byte{42, 0, 0, 0}...)
		expected = append(expected, 0x00)
		Expect(compressed).To(Equal(expected))
	})

	It("decompresses a single cert form a common certificate set", func() {
		cert := certsets.CertSet3[42]
		setHash := make([]byte, 8)
		binary.LittleEndian.PutUint64(setHash, certsets.CertSet3Hash)
		chain := [][]byte{cert}
		compressed, err := compressChain(chain, setHash, nil)
		Expect(err).ToNot(HaveOccurred())
		decompressed, err := decompressChain(compressed)
		Expect(err).ToNot(HaveOccurred())
		Expect(decompressed).To(Equal(chain))
	})

	It("decompresses multiple certs form common certificate sets", func() {
		cert1 := certsets.CertSet3[42]
		cert2 := certsets.CertSet2[24]
		setHash := make([]byte, 16)
		binary.LittleEndian.PutUint64(setHash[0:8], certsets.CertSet3Hash)
		binary.LittleEndian.PutUint64(setHash[8:16], certsets.CertSet2Hash)
		chain := [][]byte{cert1, cert2}
		compressed, err := compressChain(chain, setHash, nil)
		Expect(err).ToNot(HaveOccurred())
		decompressed, err := decompressChain(compressed)
		Expect(err).ToNot(HaveOccurred())
		Expect(decompressed).To(Equal(chain))
	})

	It("ignores uncommon certificate sets", func() {
		cert := []byte{0xde, 0xca, 0xfb, 0xad}
		setHash := make([]byte, 8)
		binary.LittleEndian.PutUint64(setHash, 0xdeadbeef)
		chain := [][]byte{cert}
		compressed, err := compressChain(chain, setHash, nil)
		Expect(err).ToNot(HaveOccurred())
		certZlib := &bytes.Buffer{}
		z, err := zlib.NewWriterLevelDict(certZlib, flate.BestCompression, certDictZlib)
		Expect(err).ToNot(HaveOccurred())
		z.Write([]byte{0x04, 0x00, 0x00, 0x00})
		z.Write(cert)
		z.Close()
		Expect(compressed).To(Equal(append([]byte{
			0x01, 0x00,
			0x08, 0x00, 0x00, 0x00,
		}, certZlib.Bytes()...)))
	})

	It("errors if a common set does not exist", func() {
		cert := certsets.CertSet3[42]
		setHash := make([]byte, 8)
		binary.LittleEndian.PutUint64(setHash, certsets.CertSet3Hash)
		chain := [][]byte{cert}
		compressed, err := compressChain(chain, setHash, nil)
		Expect(err).ToNot(HaveOccurred())
		delete(certSets, certsets.CertSet3Hash)
		_, err = decompressChain(compressed)
		Expect(err).To(MatchError(errors.New("unknown certSet")))
	})

	It("errors if a cert in a common set does not exist", func() {
		certSet := [][]byte{
			{0x1, 0x2, 0x3, 0x4},
			{0x5, 0x6, 0x7, 0x8},
		}
		certSets[0x1337] = certSet
		cert := certSet[1]
		setHash := make([]byte, 8)
		binary.LittleEndian.PutUint64(setHash, 0x1337)
		chain := [][]byte{cert}
		compressed, err := compressChain(chain, setHash, nil)
		Expect(err).ToNot(HaveOccurred())
		certSets[0x1337] = certSet[:1] // delete the last certificate from the certSet
		_, err = decompressChain(compressed)
		Expect(err).To(MatchError(errors.New("certificate not found in certSet")))
	})

	It("uses common certificates and compressed combined", func() {
		cert1 := []byte{0xde, 0xca, 0xfb, 0xad}
		cert2 := certsets.CertSet3[42]
		setHash := make([]byte, 8)
		binary.LittleEndian.PutUint64(setHash, certsets.CertSet3Hash)
		certZlib := &bytes.Buffer{}
		z, err := zlib.NewWriterLevelDict(certZlib, flate.BestCompression, append(cert2, certDictZlib...))
		Expect(err).ToNot(HaveOccurred())
		z.Write([]byte{0x04, 0x00, 0x00, 0x00})
		z.Write(cert1)
		z.Close()
		chain := [][]byte{cert1, cert2}
		compressed, err := compressChain(chain, setHash, nil)
		Expect(err).ToNot(HaveOccurred())
		expected := []byte{0x01, 0x03}
		expected = append(expected, setHash...)
		expected = append(expected, []byte{42, 0, 0, 0}...)
		expected = append(expected, 0x00)
		expected = append(expected, []byte{0x08, 0, 0, 0}...)
		expected = append(expected, certZlib.Bytes()...)
		Expect(compressed).To(Equal(expected))
	})

	It("decompresses a certficate from a common set and a compressed cert combined", func() {
		cert1 := []byte{0xde, 0xca, 0xfb, 0xad}
		cert2 := certsets.CertSet3[42]
		setHash := make([]byte, 8)
		binary.LittleEndian.PutUint64(setHash, certsets.CertSet3Hash)
		chain := [][]byte{cert1, cert2}
		compressed, err := compressChain(chain, setHash, nil)
		Expect(err).ToNot(HaveOccurred())
		decompressed, err := decompressChain(compressed)
		Expect(err).ToNot(HaveOccurred())
		Expect(decompressed).To(Equal(chain))
	})

	It("rejects invalid CCS / CCRT hashes", func() {
		cert := []byte{0xde, 0xca, 0xfb, 0xad}
		chain := [][]byte{cert}
		_, err := compressChain(chain, []byte("foo"), nil)
		Expect(err).To(MatchError("expected a multiple of 8 bytes for CCS / CCRT hashes"))
		_, err = compressChain(chain, nil, []byte("foo"))
		Expect(err).To(MatchError("expected a multiple of 8 bytes for CCS / CCRT hashes"))
	})

	Context("common certificate hashes", func() {
		It("gets the hashes", func() {
			ccs := getCommonCertificateHashes()
			Expect(ccs).ToNot(BeEmpty())
			hashes, err := splitHashes(ccs)
			Expect(err).ToNot(HaveOccurred())
			for _, hash := range hashes {
				Expect(certSets).To(HaveKey(hash))
			}
		})

		It("returns an empty slice if there are not common sets", func() {
			certSets = make(map[uint64]certSet)
			ccs := getCommonCertificateHashes()
			Expect(ccs).ToNot(BeNil())
			Expect(ccs).To(HaveLen(0))
		})
	})
})
