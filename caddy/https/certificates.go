package https

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/xenolf/lego/acme"
	"golang.org/x/crypto/ocsp"
)

// certCache stores certificates in memory,
// keying certificates by name.
var certCache = make(map[string]Certificate)
var certCacheMu sync.RWMutex

// Certificate is a tls.Certificate with associated metadata tacked on.
// Even if the metadata can be obtained by parsing the certificate,
// we can be more efficient by extracting the metadata once so it's
// just there, ready to use.
type Certificate struct {
	tls.Certificate

	// Names is the list of names this certificate is written for.
	// The first is the CommonName (if any), the rest are SAN.
	Names []string

	// NotAfter is when the certificate expires.
	NotAfter time.Time

	// Managed certificates are certificates that Caddy is managing,
	// as opposed to the user specifying a certificate and key file
	// or directory and managing the certificate resources themselves.
	Managed bool

	// OnDemand certificates are obtained or loaded on-demand during TLS
	// handshakes (as opposed to preloaded certificates, which are loaded
	// at startup). If OnDemand is true, Managed must necessarily be true.
	// OnDemand certificates are maintained in the background just like
	// preloaded ones, however, if an OnDemand certificate fails to renew,
	// it is removed from the in-memory cache.
	OnDemand bool

	// OCSP contains the certificate's parsed OCSP response.
	OCSP *ocsp.Response
}

// getCertificate gets a certificate that matches name (a server name)
// from the in-memory cache. If there is no exact match for name, it
// will be checked against names of the form '*.example.com' (wildcard
// certificates) according to RFC 6125. If a match is found, matched will
// be true. If no matches are found, matched will be false and a default
// certificate will be returned with defaulted set to true. If no default
// certificate is set, defaulted will be set to false.
//
// The logic in this function is adapted from the Go standard library,
// which is by the Go Authors.
//
// This function is safe for concurrent use.
func getCertificate(name string) (cert Certificate, matched, defaulted bool) {
	var ok bool

	// Not going to trim trailing dots here since RFC 3546 says,
	// "The hostname is represented ... without a trailing dot."
	// Just normalize to lowercase.
	name = strings.ToLower(name)

	certCacheMu.RLock()
	defer certCacheMu.RUnlock()

	// exact match? great, let's use it
	if cert, ok = certCache[name]; ok {
		matched = true
		return
	}

	// try replacing labels in the name with wildcards until we get a match
	labels := strings.Split(name, ".")
	for i := range labels {
		labels[i] = "*"
		candidate := strings.Join(labels, ".")
		if cert, ok = certCache[candidate]; ok {
			matched = true
			return
		}
	}

	// if nothing matches, use the default certificate or bust
	cert, defaulted = certCache[""]
	return
}

// cacheManagedCertificate loads the certificate for domain into the
// cache, flagging it as Managed and, if onDemand is true, as OnDemand
// (meaning that it was obtained or loaded during a TLS handshake).
//
// This function is safe for concurrent use.
func cacheManagedCertificate(domain string, onDemand bool) (Certificate, error) {
	cert, err := makeCertificateFromDisk(storage.SiteCertFile(domain), storage.SiteKeyFile(domain))
	if err != nil {
		return cert, err
	}
	cert.Managed = true
	cert.OnDemand = onDemand
	cacheCertificate(cert)
	return cert, nil
}

// cacheUnmanagedCertificatePEMFile loads a certificate for host using certFile
// and keyFile, which must be in PEM format. It stores the certificate in
// memory. The Managed and OnDemand flags of the certificate will be set to
// false.
//
// This function is safe for concurrent use.
func cacheUnmanagedCertificatePEMFile(certFile, keyFile string) error {
	cert, err := makeCertificateFromDisk(certFile, keyFile)
	if err != nil {
		return err
	}
	cacheCertificate(cert)
	return nil
}

// cacheUnmanagedCertificatePEMBytes makes a certificate out of the PEM bytes
// of the certificate and key, then caches it in memory.
//
// This function is safe for concurrent use.
func cacheUnmanagedCertificatePEMBytes(certBytes, keyBytes []byte) error {
	cert, err := makeCertificate(certBytes, keyBytes)
	if err != nil {
		return err
	}
	cacheCertificate(cert)
	return nil
}

// makeCertificateFromDisk makes a Certificate by loading the
// certificate and key files. It fills out all the fields in
// the certificate except for the Managed and OnDemand flags.
// (It is up to the caller to set those.)
func makeCertificateFromDisk(certFile, keyFile string) (Certificate, error) {
	certPEMBlock, err := ioutil.ReadFile(certFile)
	if err != nil {
		return Certificate{}, err
	}
	keyPEMBlock, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return Certificate{}, err
	}
	return makeCertificate(certPEMBlock, keyPEMBlock)
}

// makeCertificate turns a certificate PEM bundle and a key PEM block into
// a Certificate, with OCSP and other relevant metadata tagged with it,
// except for the OnDemand and Managed flags. It is up to the caller to
// set those properties.
func makeCertificate(certPEMBlock, keyPEMBlock []byte) (Certificate, error) {
	var cert Certificate

	// Convert to a tls.Certificate
	tlsCert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return cert, err
	}
	if len(tlsCert.Certificate) == 0 {
		return cert, errors.New("certificate is empty")
	}

	// Parse leaf certificate and extract relevant metadata
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return cert, err
	}
	if leaf.Subject.CommonName != "" {
		cert.Names = []string{strings.ToLower(leaf.Subject.CommonName)}
	}
	for _, name := range leaf.DNSNames {
		if name != leaf.Subject.CommonName {
			cert.Names = append(cert.Names, strings.ToLower(name))
		}
	}
	cert.NotAfter = leaf.NotAfter

	// Staple OCSP
	ocspBytes, ocspResp, err := acme.GetOCSPForCert(certPEMBlock)
	if err != nil {
		// An error here is not a problem because a certificate may simply
		// not contain a link to an OCSP server. But we should log it anyway.
		log.Printf("[WARNING] No OCSP stapling for %v: %v", cert.Names, err)
	} else if ocspResp.Status == ocsp.Good {
		tlsCert.OCSPStaple = ocspBytes
		cert.OCSP = ocspResp
	}

	cert.Certificate = tlsCert
	return cert, nil
}

// cacheCertificate adds cert to the in-memory cache. If the cache is
// empty, cert will be used as the default certificate. If the cache is
// full, random entries are deleted until there is room to map all the
// names on the certificate.
//
// This certificate will be keyed to the names in cert.Names. Any name
// that is already a key in the cache will be replaced with this cert.
//
// This function is safe for concurrent use.
func cacheCertificate(cert Certificate) {
	certCacheMu.Lock()
	if _, ok := certCache[""]; !ok {
		// use as default
		cert.Names = append(cert.Names, "")
		certCache[""] = cert
	}
	for len(certCache)+len(cert.Names) > 10000 {
		// for simplicity, just remove random elements
		for key := range certCache {
			if key == "" { // ... but not the default cert
				continue
			}
			delete(certCache, key)
			break
		}
	}
	for _, name := range cert.Names {
		certCache[name] = cert
	}
	certCacheMu.Unlock()
}
