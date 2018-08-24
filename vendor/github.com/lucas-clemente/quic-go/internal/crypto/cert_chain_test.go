package crypto

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"crypto/tls"
	"reflect"

	"github.com/lucas-clemente/quic-go/internal/testdata"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Proof", func() {
	var (
		cc     *certChain
		config *tls.Config
		cert   tls.Certificate
	)

	BeforeEach(func() {
		cert = testdata.GetCertificate()
		config = &tls.Config{}
		cc = NewCertChain(config).(*certChain)
	})

	Context("certificate compression", func() {
		It("compresses certs", func() {
			cert := []byte{0xde, 0xca, 0xfb, 0xad}
			certZlib := &bytes.Buffer{}
			z, err := zlib.NewWriterLevelDict(certZlib, flate.BestCompression, certDictZlib)
			Expect(err).ToNot(HaveOccurred())
			z.Write([]byte{0x04, 0x00, 0x00, 0x00})
			z.Write(cert)
			z.Close()
			kd := &certChain{
				config: &tls.Config{
					Certificates: []tls.Certificate{
						{Certificate: [][]byte{cert}},
					},
				},
			}
			certCompressed, err := kd.GetCertsCompressed("", nil, nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(certCompressed).To(Equal(append([]byte{
				0x01, 0x00,
				0x08, 0x00, 0x00, 0x00,
			}, certZlib.Bytes()...)))
		})

		It("errors when it can't retrieve a certificate", func() {
			_, err := cc.GetCertsCompressed("invalid domain", nil, nil)
			Expect(err).To(MatchError(errNoMatchingCertificate))
		})
	})

	Context("signing server configs", func() {
		It("errors when it can't retrieve a certificate for the requested SNI", func() {
			_, err := cc.SignServerProof("invalid", []byte("chlo"), []byte("scfg"))
			Expect(err).To(MatchError(errNoMatchingCertificate))
		})

		It("signs the server config", func() {
			config.Certificates = []tls.Certificate{cert}
			proof, err := cc.SignServerProof("", []byte("chlo"), []byte("scfg"))
			Expect(err).ToNot(HaveOccurred())
			Expect(proof).ToNot(BeEmpty())
		})
	})

	Context("retrieving certificates", func() {
		It("errors without certificates", func() {
			_, err := cc.getCertForSNI("")
			Expect(err).To(MatchError(errNoMatchingCertificate))
		})

		It("uses first certificate in config.Certificates", func() {
			config.Certificates = []tls.Certificate{cert}
			cert, err := cc.getCertForSNI("")
			Expect(err).ToNot(HaveOccurred())
			Expect(cert.PrivateKey).ToNot(BeNil())
			Expect(cert.Certificate[0]).ToNot(BeNil())
		})

		It("uses NameToCertificate entries", func() {
			config.Certificates = []tls.Certificate{cert, cert} // two entries so the long path is used
			config.NameToCertificate = map[string]*tls.Certificate{
				"quic.clemente.io": &cert,
			}
			cert, err := cc.getCertForSNI("quic.clemente.io")
			Expect(err).ToNot(HaveOccurred())
			Expect(cert.PrivateKey).ToNot(BeNil())
			Expect(cert.Certificate[0]).ToNot(BeNil())
		})

		It("uses NameToCertificate entries with wildcard", func() {
			config.Certificates = []tls.Certificate{cert, cert} // two entries so the long path is used
			config.NameToCertificate = map[string]*tls.Certificate{
				"*.clemente.io": &cert,
			}
			cert, err := cc.getCertForSNI("quic.clemente.io")
			Expect(err).ToNot(HaveOccurred())
			Expect(cert.PrivateKey).ToNot(BeNil())
			Expect(cert.Certificate[0]).ToNot(BeNil())
		})

		It("uses GetCertificate", func() {
			config.GetCertificate = func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				Expect(clientHello.ServerName).To(Equal("quic.clemente.io"))
				return &cert, nil
			}
			cert, err := cc.getCertForSNI("quic.clemente.io")
			Expect(err).ToNot(HaveOccurred())
			Expect(cert.PrivateKey).ToNot(BeNil())
			Expect(cert.Certificate[0]).ToNot(BeNil())
		})

		It("gets leaf certificates", func() {
			config.Certificates = []tls.Certificate{cert}
			cert2, err := cc.GetLeafCert("")
			Expect(err).ToNot(HaveOccurred())
			Expect(cert2).To(Equal(cert.Certificate[0]))
		})

		It("errors when it can't retrieve a leaf certificate", func() {
			_, err := cc.GetLeafCert("invalid domain")
			Expect(err).To(MatchError(errNoMatchingCertificate))
		})

		It("respects GetConfigForClient", func() {
			if !reflect.ValueOf(tls.Config{}).FieldByName("GetConfigForClient").IsValid() {
				// Pre 1.8, we don't have to do anything
				return
			}
			nestedConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
			l := func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
				Expect(chi.ServerName).To(Equal("quic.clemente.io"))
				return nestedConfig, nil
			}
			reflect.ValueOf(config).Elem().FieldByName("GetConfigForClient").Set(reflect.ValueOf(l))
			resultCert, err := cc.getCertForSNI("quic.clemente.io")
			Expect(err).NotTo(HaveOccurred())
			Expect(*resultCert).To(Equal(cert))
		})
	})
})
