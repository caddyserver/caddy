package caddytls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"time"

	"github.com/xenolf/lego/acme"
)

// loadPrivateKey loads a PEM-encoded ECC/RSA private key from an array of bytes.
func loadPrivateKey(keyBytes []byte) (crypto.PrivateKey, error) {
	keyBlock, _ := pem.Decode(keyBytes)

	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(keyBlock.Bytes)
	}

	return nil, errors.New("unknown private key type")
}

// savePrivateKey saves a PEM-encoded ECC/RSA private key to an array of bytes.
func savePrivateKey(key crypto.PrivateKey) ([]byte, error) {
	var pemType string
	var keyBytes []byte
	switch key := key.(type) {
	case *ecdsa.PrivateKey:
		var err error
		pemType = "EC"
		keyBytes, err = x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, err
		}
	case *rsa.PrivateKey:
		pemType = "RSA"
		keyBytes = x509.MarshalPKCS1PrivateKey(key)
	}

	pemKey := pem.Block{Type: pemType + " PRIVATE KEY", Bytes: keyBytes}
	return pem.EncodeToMemory(&pemKey), nil
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

// makeSelfSignedCert makes a self-signed certificate according
// to the parameters in config. It then caches the certificate
// in our cache.
func makeSelfSignedCert(config *Config) error {
	// start by generating private key
	var privKey interface{}
	var err error
	switch config.KeyType {
	case "", acme.EC256:
		privKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case acme.EC384:
		privKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case acme.RSA2048:
		privKey, err = rsa.GenerateKey(rand.Reader, 2048)
	case acme.RSA4096:
		privKey, err = rsa.GenerateKey(rand.Reader, 4096)
	case acme.RSA8192:
		privKey, err = rsa.GenerateKey(rand.Reader, 8192)
	default:
		return fmt.Errorf("cannot generate private key; unknown key type %v", config.KeyType)
	}
	if err != nil {
		return fmt.Errorf("failed to generate private key: %v", err)
	}

	// create certificate structure with proper values
	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour * 7)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %v", err)
	}
	cert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{Organization: []string{"Caddy Self-Signed"}},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(config.Hostname); ip != nil {
		cert.IPAddresses = append(cert.IPAddresses, ip)
	} else {
		cert.DNSNames = append(cert.DNSNames, config.Hostname)
	}

	publicKey := func(privKey interface{}) interface{} {
		switch k := privKey.(type) {
		case *rsa.PrivateKey:
			return &k.PublicKey
		case *ecdsa.PrivateKey:
			return &k.PublicKey
		default:
			return errors.New("unknown key type")
		}
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, publicKey(privKey), privKey)
	if err != nil {
		return fmt.Errorf("could not create certificate: %v", err)
	}

	cacheCertificate(Certificate{
		Certificate: tls.Certificate{
			Certificate: [][]byte{derBytes},
			PrivateKey:  privKey,
			Leaf:        cert,
		},
		Names:    cert.DNSNames,
		NotAfter: cert.NotAfter,
		Config:   config,
	})

	return nil
}

// RotateSessionTicketKeys rotates the TLS session ticket keys
// on cfg every TicketRotateInterval. It spawns a new goroutine so
// this function does NOT block. It returns a channel you should
// close when you are ready to stop the key rotation, like when the
// server using cfg is no longer running.
func RotateSessionTicketKeys(cfg *tls.Config) chan struct{} {
	ch := make(chan struct{})
	ticker := time.NewTicker(TicketRotateInterval)
	go runTLSTicketKeyRotation(cfg, ticker, ch)
	return ch
}

// Functions that may be swapped out for testing
var (
	runTLSTicketKeyRotation      = standaloneTLSTicketKeyRotation
	setSessionTicketKeysTestHook = func(keys [][32]byte) [][32]byte { return keys }
)

// standaloneTLSTicketKeyRotation governs over the array of TLS ticket keys used to de/crypt TLS tickets.
// It periodically sets a new ticket key as the first one, used to encrypt (and decrypt),
// pushing any old ticket keys to the back, where they are considered for decryption only.
//
// Lack of entropy for the very first ticket key results in the feature being disabled (as does Go),
// later lack of entropy temporarily disables ticket key rotation.
// Old ticket keys are still phased out, though.
//
// Stops the ticker when returning.
func standaloneTLSTicketKeyRotation(c *tls.Config, ticker *time.Ticker, exitChan chan struct{}) {
	defer ticker.Stop()

	// The entire page should be marked as sticky, but Go cannot do that
	// without resorting to syscall#Mlock. And, we don't have madvise (for NODUMP), too. ☹
	keys := make([][32]byte, 1, NumTickets)

	rng := c.Rand
	if rng == nil {
		rng = rand.Reader
	}
	if _, err := io.ReadFull(rng, keys[0][:]); err != nil {
		c.SessionTicketsDisabled = true // bail if we don't have the entropy for the first one
		return
	}
	c.SessionTicketKey = keys[0] // SetSessionTicketKeys doesn't set a 'tls.keysAlreadySet'
	c.SetSessionTicketKeys(setSessionTicketKeysTestHook(keys))

	for {
		select {
		case _, isOpen := <-exitChan:
			if !isOpen {
				return
			}
		case <-ticker.C:
			rng = c.Rand // could've changed since the start
			if rng == nil {
				rng = rand.Reader
			}
			var newTicketKey [32]byte
			_, err := io.ReadFull(rng, newTicketKey[:])

			if len(keys) < NumTickets {
				keys = append(keys, keys[0]) // manipulates the internal length
			}
			for idx := len(keys) - 1; idx >= 1; idx-- {
				keys[idx] = keys[idx-1] // yes, this makes copies
			}

			if err == nil {
				keys[0] = newTicketKey
			}
			// pushes the last key out, doesn't matter that we don't have a new one
			c.SetSessionTicketKeys(setSessionTicketKeysTestHook(keys))
		}
	}
}

const (
	// NumTickets is how many tickets to hold and consider
	// to decrypt TLS sessions.
	NumTickets = 4

	// TicketRotateInterval is how often to generate
	// new ticket for TLS PFS encryption
	TicketRotateInterval = 10 * time.Hour
)
