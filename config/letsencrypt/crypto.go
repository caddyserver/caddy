package letsencrypt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
)

// saveCertificate saves a DER-encoded (binary format) certificate
// to file.
func saveCertificate(certBytes []byte, file string) error {
	pemCert := pem.Block{Type: "CERTIFICATE", Bytes: certBytes}
	certOut, err := os.Create(file)
	if err != nil {
		return err
	}
	pem.Encode(certOut, &pemCert)
	certOut.Close()
	return nil
}

// loadRSAPrivateKey loads a PEM-encoded RSA private key from file.
func loadRSAPrivateKey(file string) (*rsa.PrivateKey, error) {
	keyBytes, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	keyBlock, _ := pem.Decode(keyBytes)
	return x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
}

// saveRSAPrivateKey saves a PEM-encoded RSA private key to file.
func saveRSAPrivateKey(key *rsa.PrivateKey, file string) error {
	pemKey := pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	keyOut, err := os.Create(file)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	return pem.Encode(keyOut, &pemKey)
}
