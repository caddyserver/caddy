package acme

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log"
)

type tlsSNIChallenge struct {
	jws      *jws
	validate validateFunc
	provider ChallengeProvider
}

func (t *tlsSNIChallenge) Solve(chlng challenge, domain string) error {
	// FIXME: https://github.com/ietf-wg-acme/acme/pull/22
	// Currently we implement this challenge to track boulder, not the current spec!

	logf("[INFO][%s] acme: Trying to solve TLS-SNI-01", domain)

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
			log.Printf("[%s] error cleaning up: %v", domain, err)
		}
	}()
	return t.validate(t.jws, domain, chlng.URI, challenge{Resource: "challenge", Type: chlng.Type, Token: chlng.Token, KeyAuthorization: keyAuth})
}

// TLSSNI01ChallengeCert returns a certificate and target domain for the `tls-sni-01` challenge
func TLSSNI01ChallengeCert(keyAuth string) (tls.Certificate, string, error) {
	// generate a new RSA key for the certificates
	tempPrivKey, err := generatePrivateKey(RSA2048)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	rsaPrivKey := tempPrivKey.(*rsa.PrivateKey)
	rsaPrivPEM := pemEncode(rsaPrivKey)

	zBytes := sha256.Sum256([]byte(keyAuth))
	z := hex.EncodeToString(zBytes[:sha256.Size])
	domain := fmt.Sprintf("%s.%s.acme.invalid", z[:32], z[32:])
	tempCertPEM, err := generatePemCert(rsaPrivKey, domain)
	if err != nil {
		return tls.Certificate{}, "", err
	}

	certificate, err := tls.X509KeyPair(tempCertPEM, rsaPrivPEM)
	if err != nil {
		return tls.Certificate{}, "", err
	}

	return certificate, domain, nil
}
