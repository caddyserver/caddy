package certificate

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/xenolf/lego/acme"
	"github.com/xenolf/lego/acme/api"
	"github.com/xenolf/lego/certcrypto"
	"github.com/xenolf/lego/challenge"
	"github.com/xenolf/lego/log"
	"github.com/xenolf/lego/platform/wait"
	"golang.org/x/crypto/ocsp"
	"golang.org/x/net/idna"
)

// maxBodySize is the maximum size of body that we will read.
const maxBodySize = 1024 * 1024

// Resource represents a CA issued certificate.
// PrivateKey, Certificate and IssuerCertificate are all
// already PEM encoded and can be directly written to disk.
// Certificate may be a certificate bundle,
// depending on the options supplied to create it.
type Resource struct {
	Domain            string `json:"domain"`
	CertURL           string `json:"certUrl"`
	CertStableURL     string `json:"certStableUrl"`
	PrivateKey        []byte `json:"-"`
	Certificate       []byte `json:"-"`
	IssuerCertificate []byte `json:"-"`
	CSR               []byte `json:"-"`
}

// ObtainRequest The request to obtain certificate.
//
// The first domain in domains is used for the CommonName field of the certificate,
// all other domains are added using the Subject Alternate Names extension.
//
// A new private key is generated for every invocation of the function Obtain.
// If you do not want that you can supply your own private key in the privateKey parameter.
// If this parameter is non-nil it will be used instead of generating a new one.
//
// If bundle is true, the []byte contains both the issuer certificate and your issued certificate as a bundle.
type ObtainRequest struct {
	Domains    []string
	Bundle     bool
	PrivateKey crypto.PrivateKey
	MustStaple bool
}

type resolver interface {
	Solve(authorizations []acme.Authorization) error
}

type CertifierOptions struct {
	KeyType certcrypto.KeyType
	Timeout time.Duration
}

// Certifier A service to obtain/renew/revoke certificates.
type Certifier struct {
	core     *api.Core
	resolver resolver
	options  CertifierOptions
}

// NewCertifier creates a Certifier.
func NewCertifier(core *api.Core, resolver resolver, options CertifierOptions) *Certifier {
	return &Certifier{
		core:     core,
		resolver: resolver,
		options:  options,
	}
}

// Obtain tries to obtain a single certificate using all domains passed into it.
//
// This function will never return a partial certificate.
// If one domain in the list fails, the whole certificate will fail.
func (c *Certifier) Obtain(request ObtainRequest) (*Resource, error) {
	if len(request.Domains) == 0 {
		return nil, errors.New("no domains to obtain a certificate for")
	}

	domains := sanitizeDomain(request.Domains)

	if request.Bundle {
		log.Infof("[%s] acme: Obtaining bundled SAN certificate", strings.Join(domains, ", "))
	} else {
		log.Infof("[%s] acme: Obtaining SAN certificate", strings.Join(domains, ", "))
	}

	order, err := c.core.Orders.New(domains)
	if err != nil {
		return nil, err
	}

	authz, err := c.getAuthorizations(order)
	if err != nil {
		// If any challenge fails, return. Do not generate partial SAN certificates.
		c.deactivateAuthorizations(order)
		return nil, err
	}

	err = c.resolver.Solve(authz)
	if err != nil {
		// If any challenge fails, return. Do not generate partial SAN certificates.
		return nil, err
	}

	log.Infof("[%s] acme: Validations succeeded; requesting certificates", strings.Join(domains, ", "))

	failures := make(obtainError)
	cert, err := c.getForOrder(domains, order, request.Bundle, request.PrivateKey, request.MustStaple)
	if err != nil {
		for _, auth := range authz {
			failures[challenge.GetTargetedDomain(auth)] = err
		}
	}

	// Do not return an empty failures map, because
	// it would still be a non-nil error value
	if len(failures) > 0 {
		return cert, failures
	}
	return cert, nil
}

// ObtainForCSR tries to obtain a certificate matching the CSR passed into it.
//
// The domains are inferred from the CommonName and SubjectAltNames, if any.
// The private key for this CSR is not required.
//
// If bundle is true, the []byte contains both the issuer certificate and your issued certificate as a bundle.
//
// This function will never return a partial certificate.
// If one domain in the list fails, the whole certificate will fail.
func (c *Certifier) ObtainForCSR(csr x509.CertificateRequest, bundle bool) (*Resource, error) {
	// figure out what domains it concerns
	// start with the common name
	domains := certcrypto.ExtractDomainsCSR(&csr)

	if bundle {
		log.Infof("[%s] acme: Obtaining bundled SAN certificate given a CSR", strings.Join(domains, ", "))
	} else {
		log.Infof("[%s] acme: Obtaining SAN certificate given a CSR", strings.Join(domains, ", "))
	}

	order, err := c.core.Orders.New(domains)
	if err != nil {
		return nil, err
	}

	authz, err := c.getAuthorizations(order)
	if err != nil {
		// If any challenge fails, return. Do not generate partial SAN certificates.
		c.deactivateAuthorizations(order)
		return nil, err
	}

	err = c.resolver.Solve(authz)
	if err != nil {
		// If any challenge fails, return. Do not generate partial SAN certificates.
		return nil, err
	}

	log.Infof("[%s] acme: Validations succeeded; requesting certificates", strings.Join(domains, ", "))

	failures := make(obtainError)
	cert, err := c.getForCSR(domains, order, bundle, csr.Raw, nil)
	if err != nil {
		for _, auth := range authz {
			failures[challenge.GetTargetedDomain(auth)] = err
		}
	}

	if cert != nil {
		// Add the CSR to the certificate so that it can be used for renewals.
		cert.CSR = certcrypto.PEMEncode(&csr)
	}

	// Do not return an empty failures map,
	// because it would still be a non-nil error value
	if len(failures) > 0 {
		return cert, failures
	}
	return cert, nil
}

func (c *Certifier) getForOrder(domains []string, order acme.ExtendedOrder, bundle bool, privateKey crypto.PrivateKey, mustStaple bool) (*Resource, error) {
	if privateKey == nil {
		var err error
		privateKey, err = certcrypto.GeneratePrivateKey(c.options.KeyType)
		if err != nil {
			return nil, err
		}
	}

	// Determine certificate name(s) based on the authorization resources
	commonName := domains[0]

	// ACME draft Section 7.4 "Applying for Certificate Issuance"
	// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.4
	// says:
	//   Clients SHOULD NOT make any assumptions about the sort order of
	//   "identifiers" or "authorizations" elements in the returned order
	//   object.
	san := []string{commonName}
	for _, auth := range order.Identifiers {
		if auth.Value != commonName {
			san = append(san, auth.Value)
		}
	}

	// TODO: should the CSR be customizable?
	csr, err := certcrypto.GenerateCSR(privateKey, commonName, san, mustStaple)
	if err != nil {
		return nil, err
	}

	return c.getForCSR(domains, order, bundle, csr, certcrypto.PEMEncode(privateKey))
}

func (c *Certifier) getForCSR(domains []string, order acme.ExtendedOrder, bundle bool, csr []byte, privateKeyPem []byte) (*Resource, error) {
	respOrder, err := c.core.Orders.UpdateForCSR(order.Finalize, csr)
	if err != nil {
		return nil, err
	}

	commonName := domains[0]
	certRes := &Resource{
		Domain:     commonName,
		CertURL:    respOrder.Certificate,
		PrivateKey: privateKeyPem,
	}

	if respOrder.Status == acme.StatusValid {
		// if the certificate is available right away, short cut!
		ok, errR := c.checkResponse(respOrder, certRes, bundle)
		if errR != nil {
			return nil, errR
		}

		if ok {
			return certRes, nil
		}
	}

	timeout := c.options.Timeout
	if c.options.Timeout <= 0 {
		timeout = 30 * time.Second
	}

	err = wait.For("certificate", timeout, timeout/60, func() (bool, error) {
		ord, errW := c.core.Orders.Get(order.Location)
		if errW != nil {
			return false, errW
		}

		done, errW := c.checkResponse(ord, certRes, bundle)
		if errW != nil {
			return false, errW
		}

		return done, nil
	})

	return certRes, err
}

// checkResponse checks to see if the certificate is ready and a link is contained in the response.
//
// If so, loads it into certRes and returns true.
// If the cert is not yet ready, it returns false.
//
// The certRes input should already have the Domain (common name) field populated.
//
// If bundle is true, the certificate will be bundled with the issuer's cert.
func (c *Certifier) checkResponse(order acme.Order, certRes *Resource, bundle bool) (bool, error) {
	valid, err := checkOrderStatus(order)
	if err != nil || !valid {
		return valid, err
	}

	cert, issuer, err := c.core.Certificates.Get(order.Certificate, bundle)
	if err != nil {
		return false, err
	}

	log.Infof("[%s] Server responded with a certificate.", certRes.Domain)

	certRes.IssuerCertificate = issuer
	certRes.Certificate = cert
	certRes.CertURL = order.Certificate
	certRes.CertStableURL = order.Certificate

	return true, nil
}

// Revoke takes a PEM encoded certificate or bundle and tries to revoke it at the CA.
func (c *Certifier) Revoke(cert []byte) error {
	certificates, err := certcrypto.ParsePEMBundle(cert)
	if err != nil {
		return err
	}

	x509Cert := certificates[0]
	if x509Cert.IsCA {
		return fmt.Errorf("certificate bundle starts with a CA certificate")
	}

	revokeMsg := acme.RevokeCertMessage{
		Certificate: base64.RawURLEncoding.EncodeToString(x509Cert.Raw),
	}

	return c.core.Certificates.Revoke(revokeMsg)
}

// Renew takes a Resource and tries to renew the certificate.
//
// If the renewal process succeeds, the new certificate will ge returned in a new CertResource.
// Please be aware that this function will return a new certificate in ANY case that is not an error.
// If the server does not provide us with a new cert on a GET request to the CertURL
// this function will start a new-cert flow where a new certificate gets generated.
//
// If bundle is true, the []byte contains both the issuer certificate and your issued certificate as a bundle.
//
// For private key reuse the PrivateKey property of the passed in Resource should be non-nil.
func (c *Certifier) Renew(certRes Resource, bundle, mustStaple bool) (*Resource, error) {
	// Input certificate is PEM encoded.
	// Decode it here as we may need the decoded cert later on in the renewal process.
	// The input may be a bundle or a single certificate.
	certificates, err := certcrypto.ParsePEMBundle(certRes.Certificate)
	if err != nil {
		return nil, err
	}

	x509Cert := certificates[0]
	if x509Cert.IsCA {
		return nil, fmt.Errorf("[%s] Certificate bundle starts with a CA certificate", certRes.Domain)
	}

	// This is just meant to be informal for the user.
	timeLeft := x509Cert.NotAfter.Sub(time.Now().UTC())
	log.Infof("[%s] acme: Trying renewal with %d hours remaining", certRes.Domain, int(timeLeft.Hours()))

	// We always need to request a new certificate to renew.
	// Start by checking to see if the certificate was based off a CSR,
	// and use that if it's defined.
	if len(certRes.CSR) > 0 {
		csr, errP := certcrypto.PemDecodeTox509CSR(certRes.CSR)
		if errP != nil {
			return nil, errP
		}

		return c.ObtainForCSR(*csr, bundle)
	}

	var privateKey crypto.PrivateKey
	if certRes.PrivateKey != nil {
		privateKey, err = certcrypto.ParsePEMPrivateKey(certRes.PrivateKey)
		if err != nil {
			return nil, err
		}
	}

	query := ObtainRequest{
		Domains:    certcrypto.ExtractDomains(x509Cert),
		Bundle:     bundle,
		PrivateKey: privateKey,
		MustStaple: mustStaple,
	}
	return c.Obtain(query)
}

// GetOCSP takes a PEM encoded cert or cert bundle returning the raw OCSP response,
// the parsed response, and an error, if any.
//
// The returned []byte can be passed directly into the OCSPStaple property of a tls.Certificate.
// If the bundle only contains the issued certificate,
// this function will try to get the issuer certificate from the IssuingCertificateURL in the certificate.
//
// If the []byte and/or ocsp.Response return values are nil, the OCSP status may be assumed OCSPUnknown.
func (c *Certifier) GetOCSP(bundle []byte) ([]byte, *ocsp.Response, error) {
	certificates, err := certcrypto.ParsePEMBundle(bundle)
	if err != nil {
		return nil, nil, err
	}

	// We expect the certificate slice to be ordered downwards the chain.
	// SRV CRT -> CA. We need to pull the leaf and issuer certs out of it,
	// which should always be the first two certificates.
	// If there's no OCSP server listed in the leaf cert, there's nothing to do.
	// And if we have only one certificate so far, we need to get the issuer cert.

	issuedCert := certificates[0]

	if len(issuedCert.OCSPServer) == 0 {
		return nil, nil, errors.New("no OCSP server specified in cert")
	}

	if len(certificates) == 1 {
		// TODO: build fallback. If this fails, check the remaining array entries.
		if len(issuedCert.IssuingCertificateURL) == 0 {
			return nil, nil, errors.New("no issuing certificate URL")
		}

		resp, errC := c.core.HTTPClient.Get(issuedCert.IssuingCertificateURL[0])
		if errC != nil {
			return nil, nil, errC
		}
		defer resp.Body.Close()

		issuerBytes, errC := ioutil.ReadAll(http.MaxBytesReader(nil, resp.Body, maxBodySize))
		if errC != nil {
			return nil, nil, errC
		}

		issuerCert, errC := x509.ParseCertificate(issuerBytes)
		if errC != nil {
			return nil, nil, errC
		}

		// Insert it into the slice on position 0
		// We want it ordered right SRV CRT -> CA
		certificates = append(certificates, issuerCert)
	}

	issuerCert := certificates[1]

	// Finally kick off the OCSP request.
	ocspReq, err := ocsp.CreateRequest(issuedCert, issuerCert, nil)
	if err != nil {
		return nil, nil, err
	}

	resp, err := c.core.HTTPClient.Post(issuedCert.OCSPServer[0], "application/ocsp-request", bytes.NewReader(ocspReq))
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	ocspResBytes, err := ioutil.ReadAll(http.MaxBytesReader(nil, resp.Body, maxBodySize))
	if err != nil {
		return nil, nil, err
	}

	ocspRes, err := ocsp.ParseResponse(ocspResBytes, issuerCert)
	if err != nil {
		return nil, nil, err
	}

	return ocspResBytes, ocspRes, nil
}

func checkOrderStatus(order acme.Order) (bool, error) {
	switch order.Status {
	case acme.StatusValid:
		return true, nil
	case acme.StatusInvalid:
		return false, order.Error
	default:
		return false, nil
	}
}

// https://tools.ietf.org/html/draft-ietf-acme-acme-16#section-7.1.4
// The domain name MUST be encoded
//   in the form in which it would appear in a certificate.  That is, it
//   MUST be encoded according to the rules in Section 7 of [RFC5280].
//
// https://tools.ietf.org/html/rfc5280#section-7
func sanitizeDomain(domains []string) []string {
	var sanitizedDomains []string
	for _, domain := range domains {
		sanitizedDomain, err := idna.ToASCII(domain)
		if err != nil {
			log.Infof("skip domain %q: unable to sanitize (punnycode): %v", domain, err)
		} else {
			sanitizedDomains = append(sanitizedDomains, sanitizedDomain)
		}
	}
	return sanitizedDomains
}
