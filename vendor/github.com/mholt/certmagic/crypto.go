// Copyright 2015 Matthew Holt
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

package certmagic

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash/fnv"

	"github.com/klauspost/cpuid"
	"github.com/xenolf/lego/certificate"
)

// encodePrivateKey marshals a EC or RSA private key into a PEM-encoded array of bytes.
func encodePrivateKey(key crypto.PrivateKey) ([]byte, error) {
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

// decodePrivateKey loads a PEM-encoded ECC/RSA private key from an array of bytes.
func decodePrivateKey(keyPEMBytes []byte) (crypto.PrivateKey, error) {
	keyBlock, _ := pem.Decode(keyPEMBytes)
	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(keyBlock.Bytes)
	}
	return nil, fmt.Errorf("unknown private key type")
}

// parseCertsFromPEMBundle parses a certificate bundle from top to bottom and returns
// a slice of x509 certificates. This function will error if no certificates are found.
func parseCertsFromPEMBundle(bundle []byte) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate
	var certDERBlock *pem.Block
	for {
		certDERBlock, bundle = pem.Decode(bundle)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(certDERBlock.Bytes)
			if err != nil {
				return nil, err
			}
			certificates = append(certificates, cert)
		}
	}
	if len(certificates) == 0 {
		return nil, fmt.Errorf("no certificates found in bundle")
	}
	return certificates, nil
}

// fastHash hashes input using a hashing algorithm that
// is fast, and returns the hash as a hex-encoded string.
// Do not use this for cryptographic purposes.
func fastHash(input []byte) string {
	h := fnv.New32a()
	h.Write(input)
	return fmt.Sprintf("%x", h.Sum32())
}

// saveCertResource saves the certificate resource to disk. This
// includes the certificate file itself, the private key, and the
// metadata file.
func (cfg *Config) saveCertResource(cert *certificate.Resource) error {
	metaBytes, err := json.MarshalIndent(&cert, "", "\t")
	if err != nil {
		return fmt.Errorf("encoding certificate metadata: %v", err)
	}

	all := []keyValue{
		{
			key:   StorageKeys.SiteCert(cfg.CA, cert.Domain),
			value: cert.Certificate,
		},
		{
			key:   StorageKeys.SitePrivateKey(cfg.CA, cert.Domain),
			value: cert.PrivateKey,
		},
		{
			key:   StorageKeys.SiteMeta(cfg.CA, cert.Domain),
			value: metaBytes,
		},
	}

	return storeTx(cfg.certCache.storage, all)
}

func (cfg *Config) loadCertResource(domain string) (certificate.Resource, error) {
	var certRes certificate.Resource
	certBytes, err := cfg.certCache.storage.Load(StorageKeys.SiteCert(cfg.CA, domain))
	if err != nil {
		return certRes, err
	}
	keyBytes, err := cfg.certCache.storage.Load(StorageKeys.SitePrivateKey(cfg.CA, domain))
	if err != nil {
		return certRes, err
	}
	metaBytes, err := cfg.certCache.storage.Load(StorageKeys.SiteMeta(cfg.CA, domain))
	if err != nil {
		return certRes, err
	}
	err = json.Unmarshal(metaBytes, &certRes)
	if err != nil {
		return certRes, fmt.Errorf("decoding certificate metadata: %v", err)
	}
	certRes.Certificate = certBytes
	certRes.PrivateKey = keyBytes
	return certRes, nil
}

// hashCertificateChain computes the unique hash of certChain,
// which is the chain of DER-encoded bytes. It returns the
// hex encoding of the hash.
func hashCertificateChain(certChain [][]byte) string {
	h := sha256.New()
	for _, certInChain := range certChain {
		h.Write(certInChain)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// preferredDefaultCipherSuites returns an appropriate
// cipher suite to use depending on hardware support
// for AES-NI.
//
// See https://github.com/mholt/caddy/issues/1674
func preferredDefaultCipherSuites() []uint16 {
	if cpuid.CPU.AesNi() {
		return defaultCiphersPreferAES
	}
	return defaultCiphersPreferChaCha
}

var (
	defaultCiphersPreferAES = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}
	defaultCiphersPreferChaCha = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}
)
