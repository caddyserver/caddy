package acme

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"strings"
	"time"

	"encoding/asn1"

	"golang.org/x/crypto/ocsp"
)

// KeyType represents the key algo as well as the key size or curve to use.
type KeyType string
type derCertificateBytes []byte

// Constants for all key types we support.
const (
	EC256   = KeyType("P256")
	EC384   = KeyType("P384")
	RSA2048 = KeyType("2048")
	RSA4096 = KeyType("4096")
	RSA8192 = KeyType("8192")
)

const (
	// OCSPGood means that the certificate is valid.
	OCSPGood = ocsp.Good
	// OCSPRevoked means that the certificate has been deliberately revoked.
	OCSPRevoked = ocsp.Revoked
	// OCSPUnknown means that the OCSP responder doesn't know about the certificate.
	OCSPUnknown = ocsp.Unknown
	// OCSPServerFailed means that the OCSP responder failed to process the request.
	OCSPServerFailed = ocsp.ServerFailed
)

// Constants for OCSP must staple
var (
	tlsFeatureExtensionOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}
	ocspMustStapleFeature  = []byte{0x30, 0x03, 0x02, 0x01, 0x05}
)

// GetOCSPForCert takes a PEM encoded cert or cert bundle returning the raw OCSP response,
// the parsed response, and an error, if any. The returned []byte can be passed directly
// into the OCSPStaple property of a tls.Certificate. If the bundle only contains the
// issued certificate, this function will try to get the issuer certificate from the
// IssuingCertificateURL in the certificate. If the []byte and/or ocsp.Response return
// values are nil, the OCSP status may be assumed OCSPUnknown.
func GetOCSPForCert(bundle []byte) ([]byte, *ocsp.Response, error) {
	certificates, err := parsePEMBundle(bundle)
	if err != nil {
		return nil, nil, err
	}

	// We expect the certificate slice to be ordered downwards the chain.
	// SRV CRT -> CA. We need to pull the leaf and issuer certs out of it,
	// which should always be the first two certificates. If there's no
	// OCSP server listed in the leaf cert, there's nothing to do. And if
	// we have only one certificate so far, we need to get the issuer cert.
	issuedCert := certificates[0]
	if len(issuedCert.OCSPServer) == 0 {
		return nil, nil, errors.New("no OCSP server specified in cert")
	}
	if len(certificates) == 1 {
		// TODO: build fallback. If this fails, check the remaining array entries.
		if len(issuedCert.IssuingCertificateURL) == 0 {
			return nil, nil, errors.New("no issuing certificate URL")
		}

		resp, err := httpGet(issuedCert.IssuingCertificateURL[0])
		if err != nil {
			return nil, nil, err
		}
		defer resp.Body.Close()

		issuerBytes, err := ioutil.ReadAll(limitReader(resp.Body, 1024*1024))
		if err != nil {
			return nil, nil, err
		}

		issuerCert, err := x509.ParseCertificate(issuerBytes)
		if err != nil {
			return nil, nil, err
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

	reader := bytes.NewReader(ocspReq)
	req, err := httpPost(issuedCert.OCSPServer[0], "application/ocsp-request", reader)
	if err != nil {
		return nil, nil, err
	}
	defer req.Body.Close()

	ocspResBytes, err := ioutil.ReadAll(limitReader(req.Body, 1024*1024))
	ocspRes, err := ocsp.ParseResponse(ocspResBytes, issuerCert)
	if err != nil {
		return nil, nil, err
	}

	return ocspResBytes, ocspRes, nil
}

func getKeyAuthorization(token string, key interface{}) (string, error) {
	var publicKey crypto.PublicKey
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		publicKey = k.Public()
	case *rsa.PrivateKey:
		publicKey = k.Public()
	}

	// Generate the Key Authorization for the challenge
	jwk := keyAsJWK(publicKey)
	if jwk == nil {
		return "", errors.New("Could not generate JWK from key.")
	}
	thumbBytes, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}

	// unpad the base64URL
	keyThumb := base64.URLEncoding.EncodeToString(thumbBytes)
	index := strings.Index(keyThumb, "=")
	if index != -1 {
		keyThumb = keyThumb[:index]
	}

	return token + "." + keyThumb, nil
}

// parsePEMBundle parses a certificate bundle from top to bottom and returns
// a slice of x509 certificates. This function will error if no certificates are found.
func parsePEMBundle(bundle []byte) ([]*x509.Certificate, error) {
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
		return nil, errors.New("No certificates were found while parsing the bundle.")
	}

	return certificates, nil
}

func parsePEMPrivateKey(key []byte) (crypto.PrivateKey, error) {
	keyBlock, _ := pem.Decode(key)

	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(keyBlock.Bytes)
	default:
		return nil, errors.New("Unknown PEM header value")
	}
}

func generatePrivateKey(keyType KeyType) (crypto.PrivateKey, error) {

	switch keyType {
	case EC256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case EC384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case RSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case RSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	case RSA8192:
		return rsa.GenerateKey(rand.Reader, 8192)
	}

	return nil, fmt.Errorf("Invalid KeyType: %s", keyType)
}

func generateCsr(privateKey crypto.PrivateKey, domain string, san []string, mustStaple bool) ([]byte, error) {
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: domain,
		},
	}

	if len(san) > 0 {
		template.DNSNames = san
	}

	if mustStaple {
		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
			Id:    tlsFeatureExtensionOID,
			Value: ocspMustStapleFeature,
		})
	}

	return x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
}

func pemEncode(data interface{}) []byte {
	var pemBlock *pem.Block
	switch key := data.(type) {
	case *ecdsa.PrivateKey:
		keyBytes, _ := x509.MarshalECPrivateKey(key)
		pemBlock = &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}
	case *rsa.PrivateKey:
		pemBlock = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
		break
	case *x509.CertificateRequest:
		pemBlock = &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: key.Raw}
		break
	case derCertificateBytes:
		pemBlock = &pem.Block{Type: "CERTIFICATE", Bytes: []byte(data.(derCertificateBytes))}
	}

	return pem.EncodeToMemory(pemBlock)
}

func pemDecode(data []byte) (*pem.Block, error) {
	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, fmt.Errorf("Pem decode did not yield a valid block. Is the certificate in the right format?")
	}

	return pemBlock, nil
}

func pemDecodeTox509(pem []byte) (*x509.Certificate, error) {
	pemBlock, err := pemDecode(pem)
	if pemBlock == nil {
		return nil, err
	}

	return x509.ParseCertificate(pemBlock.Bytes)
}

func pemDecodeTox509CSR(pem []byte) (*x509.CertificateRequest, error) {
	pemBlock, err := pemDecode(pem)
	if pemBlock == nil {
		return nil, err
	}

	if pemBlock.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("PEM block is not a certificate request")
	}

	return x509.ParseCertificateRequest(pemBlock.Bytes)
}

// GetPEMCertExpiration returns the "NotAfter" date of a PEM encoded certificate.
// The certificate has to be PEM encoded. Any other encodings like DER will fail.
func GetPEMCertExpiration(cert []byte) (time.Time, error) {
	pemBlock, err := pemDecode(cert)
	if pemBlock == nil {
		return time.Time{}, err
	}

	return getCertExpiration(pemBlock.Bytes)
}

// getCertExpiration returns the "NotAfter" date of a DER encoded certificate.
func getCertExpiration(cert []byte) (time.Time, error) {
	pCert, err := x509.ParseCertificate(cert)
	if err != nil {
		return time.Time{}, err
	}

	return pCert.NotAfter, nil
}

func generatePemCert(privKey *rsa.PrivateKey, domain string) ([]byte, error) {
	derBytes, err := generateDerCert(privKey, time.Time{}, domain)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}), nil
}

func generateDerCert(privKey *rsa.PrivateKey, expiration time.Time, domain string) ([]byte, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	if expiration.IsZero() {
		expiration = time.Now().Add(365)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "ACME Challenge TEMP",
		},
		NotBefore: time.Now(),
		NotAfter:  expiration,

		KeyUsage:              x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		DNSNames:              []string{domain},
	}

	return x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
}

func limitReader(rd io.ReadCloser, numBytes int64) io.ReadCloser {
	return http.MaxBytesReader(nil, rd, numBytes)
}
