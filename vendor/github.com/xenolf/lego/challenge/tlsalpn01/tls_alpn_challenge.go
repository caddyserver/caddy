package tlsalpn01

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	"github.com/xenolf/lego/acme"
	"github.com/xenolf/lego/acme/api"
	"github.com/xenolf/lego/certcrypto"
	"github.com/xenolf/lego/challenge"
	"github.com/xenolf/lego/log"
)

// idPeAcmeIdentifierV1 is the SMI Security for PKIX Certification Extension OID referencing the ACME extension.
// Reference: https://tools.ietf.org/html/draft-ietf-acme-tls-alpn-05#section-5.1
var idPeAcmeIdentifierV1 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}

type ValidateFunc func(core *api.Core, domain string, chlng acme.Challenge) error

type Challenge struct {
	core     *api.Core
	validate ValidateFunc
	provider challenge.Provider
}

func NewChallenge(core *api.Core, validate ValidateFunc, provider challenge.Provider) *Challenge {
	return &Challenge{
		core:     core,
		validate: validate,
		provider: provider,
	}
}

func (c *Challenge) SetProvider(provider challenge.Provider) {
	c.provider = provider
}

// Solve manages the provider to validate and solve the challenge.
func (c *Challenge) Solve(authz acme.Authorization) error {
	domain := authz.Identifier.Value
	log.Infof("[%s] acme: Trying to solve TLS-ALPN-01", challenge.GetTargetedDomain(authz))

	chlng, err := challenge.FindChallenge(challenge.TLSALPN01, authz)
	if err != nil {
		return err
	}

	// Generate the Key Authorization for the challenge
	keyAuth, err := c.core.GetKeyAuthorization(chlng.Token)
	if err != nil {
		return err
	}

	err = c.provider.Present(domain, chlng.Token, keyAuth)
	if err != nil {
		return fmt.Errorf("[%s] acme: error presenting token: %v", challenge.GetTargetedDomain(authz), err)
	}
	defer func() {
		err := c.provider.CleanUp(domain, chlng.Token, keyAuth)
		if err != nil {
			log.Warnf("[%s] acme: error cleaning up: %v", challenge.GetTargetedDomain(authz), err)
		}
	}()

	chlng.KeyAuthorization = keyAuth
	return c.validate(c.core, domain, chlng)
}

// ChallengeBlocks returns PEM blocks (certPEMBlock, keyPEMBlock) with the acmeValidation-v1 extension
// and domain name for the `tls-alpn-01` challenge.
func ChallengeBlocks(domain, keyAuth string) ([]byte, []byte, error) {
	// Compute the SHA-256 digest of the key authorization.
	zBytes := sha256.Sum256([]byte(keyAuth))

	value, err := asn1.Marshal(zBytes[:sha256.Size])
	if err != nil {
		return nil, nil, err
	}

	// Add the keyAuth digest as the acmeValidation-v1 extension
	// (marked as critical such that it won't be used by non-ACME software).
	// Reference: https://tools.ietf.org/html/draft-ietf-acme-tls-alpn-05#section-3
	extensions := []pkix.Extension{
		{
			Id:       idPeAcmeIdentifierV1,
			Critical: true,
			Value:    value,
		},
	}

	// Generate a new RSA key for the certificates.
	tempPrivateKey, err := certcrypto.GeneratePrivateKey(certcrypto.RSA2048)
	if err != nil {
		return nil, nil, err
	}

	rsaPrivateKey := tempPrivateKey.(*rsa.PrivateKey)

	// Generate the PEM certificate using the provided private key, domain, and extra extensions.
	tempCertPEM, err := certcrypto.GeneratePemCert(rsaPrivateKey, domain, extensions)
	if err != nil {
		return nil, nil, err
	}

	// Encode the private key into a PEM format. We'll need to use it to generate the x509 keypair.
	rsaPrivatePEM := certcrypto.PEMEncode(rsaPrivateKey)

	return tempCertPEM, rsaPrivatePEM, nil
}

// ChallengeCert returns a certificate with the acmeValidation-v1 extension
// and domain name for the `tls-alpn-01` challenge.
func ChallengeCert(domain, keyAuth string) (*tls.Certificate, error) {
	tempCertPEM, rsaPrivatePEM, err := ChallengeBlocks(domain, keyAuth)
	if err != nil {
		return nil, err
	}

	cert, err := tls.X509KeyPair(tempCertPEM, rsaPrivatePEM)
	if err != nil {
		return nil, err
	}

	return &cert, nil
}
