package crypto

import (
	"crypto/tls"
	"errors"
	"strings"
)

// A CertChain holds a certificate and a private key
type CertChain interface {
	SignServerProof(sni string, chlo []byte, serverConfigData []byte) ([]byte, error)
	GetCertsCompressed(sni string, commonSetHashes, cachedHashes []byte) ([]byte, error)
	GetLeafCert(sni string) ([]byte, error)
}

// proofSource stores a key and a certificate for the server proof
type certChain struct {
	config *tls.Config
}

var _ CertChain = &certChain{}

var errNoMatchingCertificate = errors.New("no matching certificate found")

// NewCertChain loads the key and cert from files
func NewCertChain(tlsConfig *tls.Config) CertChain {
	return &certChain{config: tlsConfig}
}

// SignServerProof signs CHLO and server config for use in the server proof
func (c *certChain) SignServerProof(sni string, chlo []byte, serverConfigData []byte) ([]byte, error) {
	cert, err := c.getCertForSNI(sni)
	if err != nil {
		return nil, err
	}

	return signServerProof(cert, chlo, serverConfigData)
}

// GetCertsCompressed gets the certificate in the format described by the QUIC crypto doc
func (c *certChain) GetCertsCompressed(sni string, pCommonSetHashes, pCachedHashes []byte) ([]byte, error) {
	cert, err := c.getCertForSNI(sni)
	if err != nil {
		return nil, err
	}
	return getCompressedCert(cert.Certificate, pCommonSetHashes, pCachedHashes)
}

// GetLeafCert gets the leaf certificate
func (c *certChain) GetLeafCert(sni string) ([]byte, error) {
	cert, err := c.getCertForSNI(sni)
	if err != nil {
		return nil, err
	}
	return cert.Certificate[0], nil
}

func (cc *certChain) getCertForSNI(sni string) (*tls.Certificate, error) {
	c := cc.config
	c, err := maybeGetConfigForClient(c, sni)
	if err != nil {
		return nil, err
	}
	// The rest of this function is mostly copied from crypto/tls.getCertificate

	if c.GetCertificate != nil {
		cert, err := c.GetCertificate(&tls.ClientHelloInfo{ServerName: sni})
		if cert != nil || err != nil {
			return cert, err
		}
	}

	if len(c.Certificates) == 0 {
		return nil, errNoMatchingCertificate
	}

	if len(c.Certificates) == 1 || c.NameToCertificate == nil {
		// There's only one choice, so no point doing any work.
		return &c.Certificates[0], nil
	}

	name := strings.ToLower(sni)
	for len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}

	if cert, ok := c.NameToCertificate[name]; ok {
		return cert, nil
	}

	// try replacing labels in the name with wildcards until we get a
	// match.
	labels := strings.Split(name, ".")
	for i := range labels {
		labels[i] = "*"
		candidate := strings.Join(labels, ".")
		if cert, ok := c.NameToCertificate[candidate]; ok {
			return cert, nil
		}
	}

	// If nothing matches, return the first certificate.
	return &c.Certificates[0], nil
}

func maybeGetConfigForClient(c *tls.Config, sni string) (*tls.Config, error) {
	if c.GetConfigForClient == nil {
		return c, nil
	}
	return c.GetConfigForClient(&tls.ClientHelloInfo{
		ServerName: sni,
	})
}
