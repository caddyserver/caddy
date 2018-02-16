// Copyright 2015 Light Code Labs, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
	"hash/fnv"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/mholt/caddy"
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
// If you don't have the PEM blocks already, just pass in nil.
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

	var ocspBytes []byte
	var ocspResp *ocsp.Response
	var ocspErr error
	var gotNewOCSP bool

	// First try to load OCSP staple from storage and see if
	// we can still use it.
	// TODO: Use Storage interface instead of disk directly
	var ocspFileNamePrefix string
	if len(cert.Names) > 0 {
		ocspFileNamePrefix = cert.Names[0] + "-"
	}
	ocspFileName := ocspFileNamePrefix + fastHash(pemBundle)
	ocspCachePath := filepath.Join(ocspFolder, ocspFileName)
	cachedOCSP, err := ioutil.ReadFile(ocspCachePath)
	if err == nil {
		resp, err := ocsp.ParseResponse(cachedOCSP, nil)
		if err == nil {
			if freshOCSP(resp) {
				// staple is still fresh; use it
				ocspBytes = cachedOCSP
				ocspResp = resp
			}
		} else {
			// invalid contents; delete the file
			// (we do this independently of the maintenance routine because
			// in this case we know for sure this should be a staple file
			// because we loaded it by name, whereas the maintenance routine
			// just iterates the list of files, even if somehow a non-staple
			// file gets in the folder. in this case we are sure it is corrupt.)
			err := os.Remove(ocspCachePath)
			if err != nil {
				log.Printf("[WARNING] Unable to delete invalid OCSP staple file: %v", err)
			}
		}
	}

	// If we couldn't get a fresh staple by reading the cache,
	// then we need to request it from the OCSP responder
	if ocspResp == nil || len(ocspBytes) == 0 {
		ocspBytes, ocspResp, ocspErr = acme.GetOCSPForCert(pemBundle)
		if ocspErr != nil {
			// An error here is not a problem because a certificate may simply
			// not contain a link to an OCSP server. But we should log it anyway.
			// There's nothing else we can do to get OCSP for this certificate,
			// so we can return here with the error.
			return fmt.Errorf("no OCSP stapling for %v: %v", cert.Names, ocspErr)
		}
		gotNewOCSP = true
	}

	// By now, we should have a response. If good, staple it to
	// the certificate. If the OCSP response was not loaded from
	// storage, we persist it for next time.
	if ocspResp.Status == ocsp.Good {
		if ocspResp.NextUpdate.After(cert.NotAfter) {
			// uh oh, this OCSP response expires AFTER the certificate does, that's kinda bogus.
			// it was the reason a lot of Symantec-validated sites (not Caddy) went down
			// in October 2017. https://twitter.com/mattiasgeniar/status/919432824708648961
			return fmt.Errorf("invalid: OCSP response for %v valid after certificate expiration (%s)",
				cert.Names, cert.NotAfter.Sub(ocspResp.NextUpdate))
		}
		cert.Certificate.OCSPStaple = ocspBytes
		cert.OCSP = ocspResp
		if gotNewOCSP {
			err := os.MkdirAll(filepath.Join(caddy.AssetsPath(), "ocsp"), 0700)
			if err != nil {
				return fmt.Errorf("unable to make OCSP staple path for %v: %v", cert.Names, err)
			}
			err = ioutil.WriteFile(ocspCachePath, ocspBytes, 0644)
			if err != nil {
				return fmt.Errorf("unable to write OCSP staple file for %v: %v", cert.Names, err)
			}
		}
	}

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

	chain := [][]byte{derBytes}

	config.cacheCertificate(Certificate{
		Certificate: tls.Certificate{
			Certificate: chain,
			PrivateKey:  privKey,
			Leaf:        cert,
		},
		Names:    cert.DNSNames,
		NotAfter: cert.NotAfter,
		Hash:     hashCertificateChain(chain),
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
	runTLSTicketKeyRotation        = standaloneTLSTicketKeyRotation
	setSessionTicketKeysTestHook   = func(keys [][32]byte) [][32]byte { return keys }
	setSessionTicketKeysTestHookMu sync.Mutex
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
	setSessionTicketKeysTestHookMu.Lock()
	setSessionTicketKeysHook := setSessionTicketKeysTestHook
	setSessionTicketKeysTestHookMu.Unlock()
	c.SetSessionTicketKeys(setSessionTicketKeysHook(keys))

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
			c.SetSessionTicketKeys(setSessionTicketKeysHook(keys))
		}
	}
}

// fastHash hashes input using a hashing algorithm that
// is fast, and returns the hash as a hex-encoded string.
// Do not use this for cryptographic purposes.
func fastHash(input []byte) string {
	h := fnv.New32a()
	h.Write([]byte(input))
	return fmt.Sprintf("%x", h.Sum32())
}

const (
	// NumTickets is how many tickets to hold and consider
	// to decrypt TLS sessions.
	NumTickets = 4

	// TicketRotateInterval is how often to generate
	// new ticket for TLS PFS encryption
	TicketRotateInterval = 10 * time.Hour
)
