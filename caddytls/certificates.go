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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"log"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
)

// certCache stores certificates in memory,
// keying certificates by name. Certificates
// should not overlap in the names they serve,
// because a name only maps to one certificate.
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
	// This should be the exact list of keys by which this cert
	// is accessed in the cache, careful to avoid overlap.
	Names []string

	// NotAfter is when the certificate expires.
	NotAfter time.Time

	// OCSP contains the certificate's parsed OCSP response.
	OCSP *ocsp.Response

	// Config is the configuration with which the certificate was
	// loaded or obtained and with which it should be maintained.
	Config *Config
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

// CacheManagedCertificate loads the certificate for domain into the
// cache, flagging it as Managed and, if onDemand is true, as "OnDemand"
// (meaning that it was obtained or loaded during a TLS handshake).
//
// This method is safe for concurrent use.
func (cfg *Config) CacheManagedCertificate(domain string) (Certificate, error) {
	storage, err := cfg.StorageFor(cfg.CAUrl)
	if err != nil {
		return Certificate{}, err
	}
	siteData, err := storage.LoadSite(domain)
	if err != nil {
		return Certificate{}, err
	}
	cert, err := makeCertificate(siteData.Cert, siteData.Key)
	if err != nil {
		return cert, err
	}
	cert.Config = cfg
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

	// Extract relevant metadata and staple OCSP
	err = fillCertFromLeaf(&cert, tlsCert)
	if err != nil {
		return cert, err
	}
	err = stapleOCSP(&cert, certPEMBlock)
	if err != nil {
		log.Printf("[WARNING] Stapling OCSP: %v", err)
	}

	return cert, nil
}

// fillCertFromLeaf populates metadata fields on cert from tlsCert.
func fillCertFromLeaf(cert *Certificate, tlsCert tls.Certificate) error {
	if len(tlsCert.Certificate) == 0 {
		return errors.New("certificate is empty")
	}
	cert.Certificate = tlsCert

	// the leaf cert should be the one for the site; it has what we need
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return err
	}

	if leaf.Subject.CommonName != "" {
		cert.Names = []string{strings.ToLower(leaf.Subject.CommonName)}
	}
	for _, name := range leaf.DNSNames {
		if name != leaf.Subject.CommonName {
			cert.Names = append(cert.Names, strings.ToLower(name))
		}
	}
	for _, ip := range leaf.IPAddresses {
		if ipStr := ip.String(); ipStr != leaf.Subject.CommonName {
			cert.Names = append(cert.Names, strings.ToLower(ipStr))
		}
	}
	for _, email := range leaf.EmailAddresses {
		if email != leaf.Subject.CommonName {
			cert.Names = append(cert.Names, strings.ToLower(email))
		}
	}
	if len(cert.Names) == 0 {
		return errors.New("certificate has no names")
	}

	cert.NotAfter = leaf.NotAfter

	return nil
}

// cacheCertificate adds cert to the in-memory cache. If the cache is
// empty, cert will be used as the default certificate. If the cache is
// full, random entries are deleted until there is room to map all the
// names on the certificate.
//
// This certificate will be keyed to the names in cert.Names. Any names
// already used as a cache key will NOT be replaced by this cert; in
// other words, no overlap is allowed, and this certificate will not
// service those pre-existing names.
//
// This function is safe for concurrent use.
func cacheCertificate(cert Certificate) {
	if cert.Config == nil {
		cert.Config = new(Config)
	}
	certCacheMu.Lock()
	if _, ok := certCache[""]; !ok {
		// use as default - must be *appended* to end of list, or bad things happen!
		cert.Names = append(cert.Names, "")
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
	for i := 0; i < len(cert.Names); i++ {
		name := cert.Names[i]
		if _, ok := certCache[name]; ok {
			// do not allow certificates to overlap in the names they serve;
			// this ambiguity causes problems because it is confusing while
			// maintaining certificates; see OCSP maintenance code and
			// https://caddy.community/t/random-ocsp-response-errors-for-random-clients/2473?u=matt.
			log.Printf("[NOTICE] There is already a certificate loaded for %s, "+
				"so certificate for %v will not service that name",
				name, cert.Names)
			cert.Names = append(cert.Names[:i], cert.Names[i+1:]...)
			i--
			continue
		}
		certCache[name] = cert
	}
	certCacheMu.Unlock()
}

// uncacheCertificate deletes name's certificate from the
// cache. If name is not a key in the certificate cache,
// this function does nothing.
func uncacheCertificate(name string) {
	certCacheMu.Lock()
	delete(certCache, name)
	certCacheMu.Unlock()
}
