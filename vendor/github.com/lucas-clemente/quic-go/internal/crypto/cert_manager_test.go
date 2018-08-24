package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"runtime"
	"time"

	"github.com/lucas-clemente/quic-go/internal/testdata"
	"github.com/lucas-clemente/quic-go/qerr"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Cert Manager", func() {
	var cm *certManager
	var key1, key2 *rsa.PrivateKey
	var cert1, cert2 []byte

	BeforeEach(func() {
		var err error
		cm = NewCertManager(nil).(*certManager)
		key1, err = rsa.GenerateKey(rand.Reader, 768)
		Expect(err).ToNot(HaveOccurred())
		key2, err = rsa.GenerateKey(rand.Reader, 768)
		Expect(err).ToNot(HaveOccurred())
		template := &x509.Certificate{SerialNumber: big.NewInt(1)}
		cert1, err = x509.CreateCertificate(rand.Reader, template, template, &key1.PublicKey, key1)
		Expect(err).ToNot(HaveOccurred())
		cert2, err = x509.CreateCertificate(rand.Reader, template, template, &key2.PublicKey, key2)
		Expect(err).ToNot(HaveOccurred())
	})

	It("saves a client TLS config", func() {
		tlsConf := &tls.Config{ServerName: "quic.clemente.io"}
		cm = NewCertManager(tlsConf).(*certManager)
		Expect(cm.config.ServerName).To(Equal("quic.clemente.io"))
	})

	It("errors when given invalid data", func() {
		err := cm.SetData([]byte("foobar"))
		Expect(err).To(MatchError(qerr.Error(qerr.InvalidCryptoMessageParameter, "Certificate data invalid")))
	})

	It("gets the common certificate hashes", func() {
		ccs := cm.GetCommonCertificateHashes()
		Expect(ccs).ToNot(BeEmpty())
	})

	Context("setting the data", func() {
		It("decompresses a certificate chain", func() {
			chain := [][]byte{cert1, cert2}
			compressed, err := compressChain(chain, nil, nil)
			Expect(err).ToNot(HaveOccurred())
			err = cm.SetData(compressed)
			Expect(err).ToNot(HaveOccurred())
			Expect(cm.chain[0].Raw).To(Equal(cert1))
			Expect(cm.chain[1].Raw).To(Equal(cert2))
		})

		It("errors if it can't decompress the chain", func() {
			err := cm.SetData([]byte("invalid data"))
			Expect(err).To(MatchError(qerr.Error(qerr.InvalidCryptoMessageParameter, "Certificate data invalid")))
		})

		It("errors if it can't parse a certificate", func() {
			chain := [][]byte{[]byte("cert1"), []byte("cert2")}
			compressed, err := compressChain(chain, nil, nil)
			Expect(err).ToNot(HaveOccurred())
			err = cm.SetData(compressed)
			_, ok := err.(asn1.StructuralError)
			Expect(ok).To(BeTrue())
		})
	})

	Context("getting the leaf cert", func() {
		It("gets it", func() {
			xcert1, err := x509.ParseCertificate(cert1)
			Expect(err).ToNot(HaveOccurred())
			xcert2, err := x509.ParseCertificate(cert2)
			Expect(err).ToNot(HaveOccurred())
			cm.chain = []*x509.Certificate{xcert1, xcert2}
			leafCert := cm.GetLeafCert()
			Expect(leafCert).To(Equal(cert1))
		})

		It("returns nil if the chain hasn't been set yet", func() {
			leafCert := cm.GetLeafCert()
			Expect(leafCert).To(BeNil())
		})
	})

	Context("getting the leaf cert hash", func() {
		It("calculates the FVN1a 64 hash", func() {
			cm.chain = make([]*x509.Certificate, 1)
			cm.chain[0] = &x509.Certificate{
				Raw: []byte("test fnv hash"),
			}
			hash, err := cm.GetLeafCertHash()
			Expect(err).ToNot(HaveOccurred())
			// hash calculated on http://www.nitrxgen.net/hashgen/
			Expect(hash).To(Equal(uint64(0x4770f6141fa0f5ad)))
		})

		It("errors if the certificate chain is not loaded", func() {
			_, err := cm.GetLeafCertHash()
			Expect(err).To(MatchError(errNoCertificateChain))
		})
	})

	Context("verifying the server config signature", func() {
		It("returns false when the chain hasn't been set yet", func() {
			valid := cm.VerifyServerProof([]byte("proof"), []byte("chlo"), []byte("scfg"))
			Expect(valid).To(BeFalse())
		})

		It("verifies the signature", func() {
			chlo := []byte("client hello")
			scfg := []byte("server config data")
			xcert1, err := x509.ParseCertificate(cert1)
			Expect(err).ToNot(HaveOccurred())
			cm.chain = []*x509.Certificate{xcert1}
			proof, err := signServerProof(&tls.Certificate{PrivateKey: key1}, chlo, scfg)
			Expect(err).ToNot(HaveOccurred())
			valid := cm.VerifyServerProof(proof, chlo, scfg)
			Expect(valid).To(BeTrue())
		})

		It("rejects an invalid signature", func() {
			xcert1, err := x509.ParseCertificate(cert1)
			Expect(err).ToNot(HaveOccurred())
			cm.chain = []*x509.Certificate{xcert1}
			valid := cm.VerifyServerProof([]byte("invalid proof"), []byte("chlo"), []byte("scfg"))
			Expect(valid).To(BeFalse())
		})
	})

	Context("verifying the certificate chain", func() {
		generateCertificate := func(template, parent *x509.Certificate, pubKey *rsa.PublicKey, privKey *rsa.PrivateKey) *x509.Certificate {
			certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pubKey, privKey)
			Expect(err).ToNot(HaveOccurred())
			cert, err := x509.ParseCertificate(certDER)
			Expect(err).ToNot(HaveOccurred())
			return cert
		}

		getCertificate := func(template *x509.Certificate) (*rsa.PrivateKey, *x509.Certificate) {
			key, err := rsa.GenerateKey(rand.Reader, 1024)
			Expect(err).ToNot(HaveOccurred())
			return key, generateCertificate(template, template, &key.PublicKey, key)
		}

		It("accepts a valid certificate", func() {
			cc := NewCertChain(testdata.GetTLSConfig()).(*certChain)
			tlsCert, err := cc.getCertForSNI("quic.clemente.io")
			Expect(err).ToNot(HaveOccurred())
			for _, data := range tlsCert.Certificate {
				var cert *x509.Certificate
				cert, err = x509.ParseCertificate(data)
				Expect(err).ToNot(HaveOccurred())
				cm.chain = append(cm.chain, cert)
			}
			err = cm.Verify("quic.clemente.io")
			Expect(err).ToNot(HaveOccurred())
		})

		It("doesn't accept an expired certificate", func() {
			if runtime.GOOS == "windows" {
				// certificate validation works different on windows, see https://golang.org/src/crypto/x509/verify.go line 238
				Skip("windows")
			}

			template := &x509.Certificate{
				SerialNumber: big.NewInt(1),
				NotBefore:    time.Now().Add(-25 * time.Hour),
				NotAfter:     time.Now().Add(-time.Hour),
			}
			_, leafCert := getCertificate(template)

			cm.chain = []*x509.Certificate{leafCert}
			err := cm.Verify("")
			Expect(err).To(HaveOccurred())
			Expect(err.(x509.CertificateInvalidError).Reason).To(Equal(x509.Expired))
		})

		It("doesn't accept a certificate that is not yet valid", func() {
			if runtime.GOOS == "windows" {
				// certificate validation works different on windows, see https://golang.org/src/crypto/x509/verify.go line 238
				Skip("windows")
			}

			template := &x509.Certificate{
				SerialNumber: big.NewInt(1),
				NotBefore:    time.Now().Add(time.Hour),
				NotAfter:     time.Now().Add(25 * time.Hour),
			}
			_, leafCert := getCertificate(template)

			cm.chain = []*x509.Certificate{leafCert}
			err := cm.Verify("")
			Expect(err).To(HaveOccurred())
			Expect(err.(x509.CertificateInvalidError).Reason).To(Equal(x509.Expired))
		})

		It("doesn't accept an certificate for the wrong hostname", func() {
			if runtime.GOOS == "windows" {
				// certificate validation works different on windows, see https://golang.org/src/crypto/x509/verify.go line 238
				Skip("windows")
			}

			template := &x509.Certificate{
				SerialNumber: big.NewInt(1),
				NotBefore:    time.Now().Add(-time.Hour),
				NotAfter:     time.Now().Add(time.Hour),
				Subject:      pkix.Name{CommonName: "google.com"},
			}
			_, leafCert := getCertificate(template)

			cm.chain = []*x509.Certificate{leafCert}
			err := cm.Verify("quic.clemente.io")
			Expect(err).To(HaveOccurred())
			_, ok := err.(x509.HostnameError)
			Expect(ok).To(BeTrue())
		})

		It("errors if the chain hasn't been set yet", func() {
			err := cm.Verify("example.com")
			Expect(err).To(HaveOccurred())
		})

		// this tests relies on LetsEncrypt not being contained in the Root CAs
		It("rejects valid certificate with missing certificate chain", func() {
			if runtime.GOOS == "windows" {
				Skip("LetsEncrypt Root CA is included in Windows")
			}

			cert := testdata.GetCertificate()
			xcert, err := x509.ParseCertificate(cert.Certificate[0])
			Expect(err).ToNot(HaveOccurred())
			cm.chain = []*x509.Certificate{xcert}
			err = cm.Verify("quic.clemente.io")
			_, ok := err.(x509.UnknownAuthorityError)
			Expect(ok).To(BeTrue())
		})

		It("doesn't do any certificate verification if InsecureSkipVerify is set", func() {
			if runtime.GOOS == "windows" {
				// certificate validation works different on windows, see https://golang.org/src/crypto/x509/verify.go line 238
				Skip("windows")
			}

			template := &x509.Certificate{
				SerialNumber: big.NewInt(1),
			}

			_, leafCert := getCertificate(template)
			cm.config = &tls.Config{
				InsecureSkipVerify: true,
			}
			cm.chain = []*x509.Certificate{leafCert}
			err := cm.Verify("quic.clemente.io")
			Expect(err).ToNot(HaveOccurred())
		})

		It("uses the time specified in a client TLS config", func() {
			if runtime.GOOS == "windows" {
				// certificate validation works different on windows, see https://golang.org/src/crypto/x509/verify.go line 238
				Skip("windows")
			}

			template := &x509.Certificate{
				SerialNumber: big.NewInt(1),
				NotBefore:    time.Now().Add(-25 * time.Hour),
				NotAfter:     time.Now().Add(-23 * time.Hour),
				Subject:      pkix.Name{CommonName: "quic.clemente.io"},
			}
			_, leafCert := getCertificate(template)
			cm.chain = []*x509.Certificate{leafCert}
			cm.config = &tls.Config{
				Time: func() time.Time { return time.Now().Add(-24 * time.Hour) },
			}
			err := cm.Verify("quic.clemente.io")
			_, ok := err.(x509.UnknownAuthorityError)
			Expect(ok).To(BeTrue())
		})

		It("rejects certificates that are expired at the time specified in a client TLS config", func() {
			if runtime.GOOS == "windows" {
				// certificate validation works different on windows, see https://golang.org/src/crypto/x509/verify.go line 238
				Skip("windows")
			}

			template := &x509.Certificate{
				SerialNumber: big.NewInt(1),
				NotBefore:    time.Now().Add(-time.Hour),
				NotAfter:     time.Now().Add(time.Hour),
			}
			_, leafCert := getCertificate(template)
			cm.chain = []*x509.Certificate{leafCert}
			cm.config = &tls.Config{
				Time: func() time.Time { return time.Now().Add(-24 * time.Hour) },
			}
			err := cm.Verify("quic.clemente.io")
			Expect(err.(x509.CertificateInvalidError).Reason).To(Equal(x509.Expired))
		})

		It("uses the Root CA given in the client config", func() {
			if runtime.GOOS == "windows" {
				// certificate validation works different on windows, see https://golang.org/src/crypto/x509/verify.go line 238
				Skip("windows")
			}

			templateRoot := &x509.Certificate{
				SerialNumber:          big.NewInt(1),
				NotBefore:             time.Now().Add(-time.Hour),
				NotAfter:              time.Now().Add(time.Hour),
				IsCA:                  true,
				BasicConstraintsValid: true,
			}
			rootKey, rootCert := getCertificate(templateRoot)
			template := &x509.Certificate{
				SerialNumber: big.NewInt(1),
				NotBefore:    time.Now().Add(-time.Hour),
				NotAfter:     time.Now().Add(time.Hour),
				Subject:      pkix.Name{CommonName: "google.com"},
			}
			key, err := rsa.GenerateKey(rand.Reader, 1024)
			Expect(err).ToNot(HaveOccurred())
			leafCert := generateCertificate(template, rootCert, &key.PublicKey, rootKey)

			rootCAPool := x509.NewCertPool()
			rootCAPool.AddCert(rootCert)

			cm.chain = []*x509.Certificate{leafCert}
			cm.config = &tls.Config{
				RootCAs: rootCAPool,
			}
			err = cm.Verify("google.com")
			Expect(err).ToNot(HaveOccurred())
		})
	})
})
