package api

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"net/http"

	"github.com/xenolf/lego/acme"
	"github.com/xenolf/lego/certcrypto"
	"github.com/xenolf/lego/log"
)

// maxBodySize is the maximum size of body that we will read.
const maxBodySize = 1024 * 1024

type CertificateService service

// Get Returns the certificate and the issuer certificate.
// 'bundle' is only applied if the issuer is provided by the 'up' link.
func (c *CertificateService) Get(certURL string, bundle bool) ([]byte, []byte, error) {
	cert, up, err := c.get(certURL)
	if err != nil {
		return nil, nil, err
	}

	// Get issuerCert from bundled response from Let's Encrypt
	// See https://community.letsencrypt.org/t/acme-v2-no-up-link-in-response/64962
	_, issuer := pem.Decode(cert)
	if issuer != nil {
		return cert, issuer, nil
	}

	issuer, err = c.getIssuerFromLink(up)
	if err != nil {
		// If we fail to acquire the issuer cert, return the issued certificate - do not fail.
		log.Warnf("acme: Could not bundle issuer certificate [%s]: %v", certURL, err)
	} else if len(issuer) > 0 {
		// If bundle is true, we want to return a certificate bundle.
		// To do this, we append the issuer cert to the issued cert.
		if bundle {
			cert = append(cert, issuer...)
		}
	}

	return cert, issuer, nil
}

// Revoke Revokes a certificate.
func (c *CertificateService) Revoke(req acme.RevokeCertMessage) error {
	_, err := c.core.post(c.core.GetDirectory().RevokeCertURL, req, nil)
	return err
}

// get Returns the certificate and the "up" link.
func (c *CertificateService) get(certURL string) ([]byte, string, error) {
	if len(certURL) == 0 {
		return nil, "", errors.New("certificate[get]: empty URL")
	}

	resp, err := c.core.postAsGet(certURL, nil)
	if err != nil {
		return nil, "", err
	}

	cert, err := ioutil.ReadAll(http.MaxBytesReader(nil, resp.Body, maxBodySize))
	if err != nil {
		return nil, "", err
	}

	// The issuer certificate link may be supplied via an "up" link
	// in the response headers of a new certificate.
	// See https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.4.2
	up := getLink(resp.Header, "up")

	return cert, up, err
}

// getIssuerFromLink requests the issuer certificate
func (c *CertificateService) getIssuerFromLink(up string) ([]byte, error) {
	if len(up) == 0 {
		return nil, nil
	}

	log.Infof("acme: Requesting issuer cert from %s", up)

	cert, _, err := c.get(up)
	if err != nil {
		return nil, err
	}

	_, err = x509.ParseCertificate(cert)
	if err != nil {
		return nil, err
	}

	return certcrypto.PEMEncode(certcrypto.DERCertificateBytes(cert)), nil
}
