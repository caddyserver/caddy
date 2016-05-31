package caddytls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"

	"github.com/xenolf/lego/acme"
)

// loadPrivateKey loads a PEM-encoded ECC/RSA private key from file.
func loadPrivateKey(file string) (crypto.PrivateKey, error) {
	keyBytes, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	keyBlock, _ := pem.Decode(keyBytes)

	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(keyBlock.Bytes)
	}

	return nil, errors.New("unknown private key type")
}

// savePrivateKey saves a PEM-encoded ECC/RSA private key to file.
func savePrivateKey(key crypto.PrivateKey, file string) error {
	var pemType string
	var keyBytes []byte
	switch key := key.(type) {
	case *ecdsa.PrivateKey:
		var err error
		pemType = "EC"
		keyBytes, err = x509.MarshalECPrivateKey(key)
		if err != nil {
			return err
		}
	case *rsa.PrivateKey:
		pemType = "RSA"
		keyBytes = x509.MarshalPKCS1PrivateKey(key)
	}

	pemKey := pem.Block{Type: pemType + " PRIVATE KEY", Bytes: keyBytes}
	keyOut, err := os.Create(file)
	if err != nil {
		return err
	}
	keyOut.Chmod(0600)
	defer keyOut.Close()
	return pem.Encode(keyOut, &pemKey)
}

// stapleOCSP staples OCSP information to cert for hostname name.
// If you have it handy, you should pass in the PEM-encoded certificate
// bundle; otherwise the DER-encoded cert will have to be PEM-encoded.
// If you don't have the PEM blocks handy, just pass in nil.
//
// Errors here are not necessarily fatal, it could just be that the
// certificate doesn't have an issuer URL.
func stapleOCSP(cert *Certificate, pemBundle []byte) error {
	if pemBundle == nil {
		// The function in the acme package that gets OCSP requires a PEM-encoded cert
		bundle := new(bytes.Buffer)
		for _, derBytes := range cert.Certificate.Certificate {
			pem.Encode(bundle, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
		}
		pemBundle = bundle.Bytes()
	}

	ocspBytes, ocspResp, err := acme.GetOCSPForCert(pemBundle)
	if err != nil {
		return err
	}

	cert.Certificate.OCSPStaple = ocspBytes
	cert.OCSP = ocspResp

	return nil
}
