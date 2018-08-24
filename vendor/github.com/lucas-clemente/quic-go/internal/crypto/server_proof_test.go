package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"math/big"

	"github.com/lucas-clemente/quic-go/internal/testdata"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Proof", func() {
	It("gives valid signatures with the key in internal/testdata", func() {
		key := &testdata.GetTLSConfig().Certificates[0]
		signature, err := signServerProof(key, []byte{'C', 'H', 'L', 'O'}, []byte{'S', 'C', 'F', 'G'})
		Expect(err).ToNot(HaveOccurred())
		// Generated with:
		// ruby -e 'require "digest"; p Digest::SHA256.digest("QUIC CHLO and server config signature\x00" + "\x20\x00\x00\x00" + Digest::SHA256.digest("CHLO") + "SCFG")'
		data := []byte("W\xA6\xFC\xDE\xC7\xD2>c\xE6\xB5\xF6\tq\x9E|<~1\xA33\x01\xCA=\x19\xBD\xC1\xE4\xB0\xBA\x9B\x16%")
		err = rsa.VerifyPSS(key.PrivateKey.(*rsa.PrivateKey).Public().(*rsa.PublicKey), crypto.SHA256, data, signature, &rsa.PSSOptions{SaltLength: 32})
		Expect(err).ToNot(HaveOccurred())
	})

	Context("when using RSA", func() {
		generateCert := func() (*rsa.PrivateKey, *x509.Certificate) {
			key, err := rsa.GenerateKey(rand.Reader, 1024)
			Expect(err).NotTo(HaveOccurred())

			certTemplate := x509.Certificate{SerialNumber: big.NewInt(1)}
			certDER, err := x509.CreateCertificate(rand.Reader, &certTemplate, &certTemplate, &key.PublicKey, key)
			Expect(err).ToNot(HaveOccurred())
			cert, err := x509.ParseCertificate(certDER)
			Expect(err).ToNot(HaveOccurred())

			return key, cert
		}

		It("verifies a signature", func() {
			key, cert := generateCert()
			chlo := []byte("chlo")
			scfg := []byte("scfg")
			signature, err := signServerProof(&tls.Certificate{PrivateKey: key}, chlo, scfg)
			Expect(err).ToNot(HaveOccurred())
			Expect(verifyServerProof(signature, cert, chlo, scfg)).To(BeTrue())
		})

		It("rejects invalid signatures", func() {
			key, cert := generateCert()
			chlo := []byte("client hello")
			scfg := []byte("sever config")
			signature, err := signServerProof(&tls.Certificate{PrivateKey: key}, chlo, scfg)
			Expect(err).ToNot(HaveOccurred())
			Expect(verifyServerProof(append(signature, byte(0x99)), cert, chlo, scfg)).To(BeFalse())
			Expect(verifyServerProof(signature, cert, chlo[:len(chlo)-2], scfg)).To(BeFalse())
			Expect(verifyServerProof(signature, cert, chlo, scfg[:len(scfg)-2])).To(BeFalse())
		})
	})

	Context("when using ECDSA", func() {
		generateCert := func() (*ecdsa.PrivateKey, *x509.Certificate) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			Expect(err).NotTo(HaveOccurred())

			certTemplate := x509.Certificate{SerialNumber: big.NewInt(1)}
			certDER, err := x509.CreateCertificate(rand.Reader, &certTemplate, &certTemplate, &key.PublicKey, key)
			Expect(err).ToNot(HaveOccurred())
			cert, err := x509.ParseCertificate(certDER)
			Expect(err).ToNot(HaveOccurred())

			return key, cert
		}

		It("gives valid signatures", func() {
			key, _ := generateCert()
			signature, err := signServerProof(&tls.Certificate{PrivateKey: key}, []byte{'C', 'H', 'L', 'O'}, []byte{'S', 'C', 'F', 'G'})
			Expect(err).ToNot(HaveOccurred())
			// Generated with:
			// ruby -e 'require "digest"; p Digest::SHA256.digest("QUIC CHLO and server config signature\x00" + "\x20\x00\x00\x00" + Digest::SHA256.digest("CHLO") + "SCFG")'
			data := []byte("W\xA6\xFC\xDE\xC7\xD2>c\xE6\xB5\xF6\tq\x9E|<~1\xA33\x01\xCA=\x19\xBD\xC1\xE4\xB0\xBA\x9B\x16%")
			s := &ecdsaSignature{}
			_, err = asn1.Unmarshal(signature, s)
			Expect(err).NotTo(HaveOccurred())
			b := ecdsa.Verify(key.Public().(*ecdsa.PublicKey), data, s.R, s.S)
			Expect(b).To(BeTrue())
		})

		It("verifies a signature", func() {
			key, cert := generateCert()
			chlo := []byte("chlo")
			scfg := []byte("server config")
			signature, err := signServerProof(&tls.Certificate{PrivateKey: key}, chlo, scfg)
			Expect(err).ToNot(HaveOccurred())
			Expect(verifyServerProof(signature, cert, chlo, scfg)).To(BeTrue())
		})

		It("rejects invalid signatures", func() {
			key, cert := generateCert()
			chlo := []byte("client hello")
			scfg := []byte("server config")
			signature, err := signServerProof(&tls.Certificate{PrivateKey: key}, chlo, scfg)
			Expect(err).ToNot(HaveOccurred())
			Expect(verifyServerProof(append(signature, byte(0x99)), cert, chlo, scfg)).To(BeFalse())
			Expect(verifyServerProof(signature, cert, chlo[:len(chlo)-2], scfg)).To(BeFalse())
			Expect(verifyServerProof(signature, cert, chlo, scfg[:len(scfg)-2])).To(BeFalse())
		})

		It("rejects signatures generated with a different certificate", func() {
			key1, cert1 := generateCert()
			key2, cert2 := generateCert()
			Expect(key1.PublicKey).ToNot(Equal(key2))
			Expect(cert1.Equal(cert2)).To(BeFalse())
			chlo := []byte("chlo")
			scfg := []byte("sfcg")
			signature, err := signServerProof(&tls.Certificate{PrivateKey: key1}, chlo, scfg)
			Expect(err).ToNot(HaveOccurred())
			Expect(verifyServerProof(signature, cert2, chlo, scfg)).To(BeFalse())
		})
	})
})
