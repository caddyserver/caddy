package acme

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	"github.com/xenolf/lego/log"
)

// idPeAcmeIdentifierV1 is the SMI Security for PKIX Certification Extension OID referencing the ACME extension.
// Reference: https://tools.ietf.org/html/draft-ietf-acme-tls-alpn-01#section-5.1
var idPeAcmeIdentifierV1 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 30, 1}

type tlsALPNChallenge struct {
	jws      *jws
	validate validateFunc
	provider ChallengeProvider
}

// Solve manages the provider to validate and solve the challenge.
func (t *tlsALPNChallenge) Solve(chlng challenge, domain string) error {
	log.Infof("[%s] acme: Trying to solve TLS-ALPN-01", domain)

	// Generate the Key Authorization for the challenge
	keyAuth, err := getKeyAuthorization(chlng.Token, t.jws.privKey)
	if err != nil {
		return err
	}

	err = t.provider.Present(domain, chlng.Token, keyAuth)
	if err != nil {
		return fmt.Errorf("[%s] error presenting token: %v", domain, err)
	}
	defer func() {
		err := t.provider.CleanUp(domain, chlng.Token, keyAuth)
		if err != nil {
			log.Warnf("[%s] error cleaning up: %v", domain, err)
		}
	}()

	return t.validate(t.jws, domain, chlng.URL, challenge{Type: chlng.Type, Token: chlng.Token, KeyAuthorization: keyAuth})
}

// TLSALPNChallengeBlocks returns PEM blocks (certPEMBlock, keyPEMBlock) with the acmeValidation-v1 extension
// and domain name for the `tls-alpn-01` challenge.
func TLSALPNChallengeBlocks(domain, keyAuth string) ([]byte, []byte, error) {
	// Compute the SHA-256 digest of the key authorization.
	zBytes := sha256.Sum256([]byte(keyAuth))

	value, err := asn1.Marshal(zBytes[:sha256.Size])
	if err != nil {
		return nil, nil, err
	}

	// Add the keyAuth digest as the acmeValidation-v1 extension
	// (marked as critical such that it won't be used by non-ACME software).
	// Reference: https://tools.ietf.org/html/draft-ietf-acme-tls-alpn-01#section-3
	extensions := []pkix.Extension{
		{
			Id:       idPeAcmeIdentifierV1,
			Critical: true,
			Value:    value,
		},
	}

	// Generate a new RSA key for the certificates.
	tempPrivKey, err := generatePrivateKey(RSA2048)
	if err != nil {
		return nil, nil, err
	}

	rsaPrivKey := tempPrivKey.(*rsa.PrivateKey)

	// Generate the PEM certificate using the provided private key, domain, and extra extensions.
	tempCertPEM, err := generatePemCert(rsaPrivKey, domain, extensions)
	if err != nil {
		return nil, nil, err
	}

	// Encode the private key into a PEM format. We'll need to use it to generate the x509 keypair.
	rsaPrivPEM := pemEncode(rsaPrivKey)

	return tempCertPEM, rsaPrivPEM, nil
}

// TLSALPNChallengeCert returns a certificate with the acmeValidation-v1 extension
// and domain name for the `tls-alpn-01` challenge.
func TLSALPNChallengeCert(domain, keyAuth string) (*tls.Certificate, error) {
	tempCertPEM, rsaPrivPEM, err := TLSALPNChallengeBlocks(domain, keyAuth)
	if err != nil {
		return nil, err
	}

	certificate, err := tls.X509KeyPair(tempCertPEM, rsaPrivPEM)
	if err != nil {
		return nil, err
	}

	return &certificate, nil
}
