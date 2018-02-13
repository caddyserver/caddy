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
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
)

// certificateCache is to be an instance-wide cache of certs
// that site-specific TLS configs can refer to. Using a
// central map like this avoids duplication of certs in
// memory when the cert is used by multiple sites, and makes
// maintenance easier. Because these are not to be global,
// the cache will get garbage collected after a config reload
// (a new instance will take its place).
type certificateCache struct {
	sync.RWMutex
	cache map[string]Certificate // keyed by certificate hash
}

// replaceCertificate replaces oldCert with newCert in the cache, and
// updates all configs that are pointing to the old certificate to
// point to the new one instead. newCert must already be loaded into
// the cache (this method does NOT load it into the cache).
//
// Note that all the names on the old certificate will be deleted
// from the name lookup maps of each config, then all the names on
// the new certificate will be added to the lookup maps as long as
// they do not overwrite any entries.
//
// The newCert may be modified and its cache entry updated.
//
// This method is safe for concurrent use.
func (certCache *certificateCache) replaceCertificate(oldCert, newCert Certificate) error {
	certCache.Lock()
	defer certCache.Unlock()

	// have all the configs that are pointing to the old
	// certificate point to the new certificate instead
	for _, cfg := range oldCert.configs {
		// first delete all the name lookup entries that
		// pointed to the old certificate
		for name, certKey := range cfg.Certificates {
			if certKey == oldCert.Hash {
				delete(cfg.Certificates, name)
			}
		}

		// then add name lookup entries for the names
		// on the new certificate, but don't overwrite
		// entries that may already exist, not only as
		// a courtesy, but importantly: because if we
		// overwrote a value here, and this config no
		// longer pointed to a certain certificate in
		// the cache, that certificate's list of configs
		// referring to it would be incorrect; so just
		// insert entries, don't overwrite any
		for _, name := range newCert.Names {
			if _, ok := cfg.Certificates[name]; !ok {
				cfg.Certificates[name] = newCert.Hash
			}
		}
	}

	// since caching a new certificate attaches only the config
	// that loaded it, the new certificate needs to be given the
	// list of all the configs that use it, so copy the list
	// over from the old certificate to the new certificate
	// in the cache
	newCert.configs = oldCert.configs
	certCache.cache[newCert.Hash] = newCert

	// finally, delete the old certificate from the cache
	delete(certCache.cache, oldCert.Hash)

	return nil
}

// reloadManagedCertificate reloads the certificate corresponding to the name(s)
// on oldCert into the cache, from storage. This also replaces the old certificate
// with the new one, so that all configurations that used the old cert now point
// to the new cert.
func (certCache *certificateCache) reloadManagedCertificate(oldCert Certificate) error {
	// get the certificate from storage and cache it
	newCert, err := oldCert.configs[0].CacheManagedCertificate(oldCert.Names[0])
	if err != nil {
		return fmt.Errorf("unable to reload certificate for %v into cache: %v", oldCert.Names, err)
	}

	// and replace the old certificate with the new one
	err = certCache.replaceCertificate(oldCert, newCert)
	if err != nil {
		return fmt.Errorf("replacing certificate %v: %v", oldCert.Names, err)
	}

	return nil
}

// Certificate is a tls.Certificate with associated metadata tacked on.
// Even if the metadata can be obtained by parsing the certificate,
// we are more efficient by extracting the metadata onto this struct.
type Certificate struct {
	tls.Certificate

	// Names is the list of names this certificate is written for.
	// The first is the CommonName (if any), the rest are SAN.
	Names []string

	// NotAfter is when the certificate expires.
	NotAfter time.Time

	// OCSP contains the certificate's parsed OCSP response.
	OCSP *ocsp.Response

	// The hex-encoded hash of this cert's chain's bytes.
	Hash string

	// configs is the list of configs that use or refer to
	// The first one is assumed to be the config that is
	// "in charge" of this certificate (i.e. determines
	// whether it is managed, how it is managed, etc).
	// This field will be populated by cacheCertificate.
	// Only meddle with it if you know what you're doing!
	configs []*Config
}

// CacheManagedCertificate loads the certificate for domain into the
// cache, from the TLS storage for managed certificates. It returns a
// copy of the Certificate that was put into the cache.
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
	cert, err := makeCertificateWithOCSP(siteData.Cert, siteData.Key)
	if err != nil {
		return cert, err
	}
	return cfg.cacheCertificate(cert), nil
}

// cacheUnmanagedCertificatePEMFile loads a certificate for host using certFile
// and keyFile, which must be in PEM format. It stores the certificate in
// the in-memory cache.
//
// This function is safe for concurrent use.
func (cfg *Config) cacheUnmanagedCertificatePEMFile(certFile, keyFile string) error {
	cert, err := makeCertificateFromDiskWithOCSP(certFile, keyFile)
	if err != nil {
		return err
	}
	cfg.cacheCertificate(cert)
	return nil
}

// cacheUnmanagedCertificatePEMBytes makes a certificate out of the PEM bytes
// of the certificate and key, then caches it in memory.
//
// This function is safe for concurrent use.
func (cfg *Config) cacheUnmanagedCertificatePEMBytes(certBytes, keyBytes []byte) error {
	cert, err := makeCertificateWithOCSP(certBytes, keyBytes)
	if err != nil {
		return err
	}
	cfg.cacheCertificate(cert)
	return nil
}

// makeCertificateFromDiskWithOCSP makes a Certificate by loading the
// certificate and key files. It fills out all the fields in
// the certificate except for the Managed and OnDemand flags.
// (It is up to the caller to set those.) It staples OCSP.
func makeCertificateFromDiskWithOCSP(certFile, keyFile string) (Certificate, error) {
	certPEMBlock, err := ioutil.ReadFile(certFile)
	if err != nil {
		return Certificate{}, err
	}
	keyPEMBlock, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return Certificate{}, err
	}
	return makeCertificateWithOCSP(certPEMBlock, keyPEMBlock)
}

// makeCertificate turns a certificate PEM bundle and a key PEM block into
// a Certificate with necessary metadata from parsing its bytes filled into
// its struct fields for convenience (except for the OnDemand and Managed
// flags; it is up to the caller to set those properties!). This function
// does NOT staple OCSP.
func makeCertificate(certPEMBlock, keyPEMBlock []byte) (Certificate, error) {
	var cert Certificate

	// Convert to a tls.Certificate
	tlsCert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return cert, err
	}

	// Extract necessary metadata
	err = fillCertFromLeaf(&cert, tlsCert)
	if err != nil {
		return cert, err
	}

	return cert, nil
}

// makeCertificateWithOCSP is the same as makeCertificate except that it also
// staples OCSP to the certificate.
func makeCertificateWithOCSP(certPEMBlock, keyPEMBlock []byte) (Certificate, error) {
	cert, err := makeCertificate(certPEMBlock, keyPEMBlock)
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

	// save the hash of this certificate (chain) and
	// expiration date, for necessity and efficiency
	cert.Hash = hashCertificateChain(cert.Certificate.Certificate)
	cert.NotAfter = leaf.NotAfter

	return nil
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

// managedCertInStorageExpiresSoon returns true if cert (being a
// managed certificate) is expiring within RenewDurationBefore.
// It returns false if there was an error checking the expiration
// of the certificate as found in storage, or if the certificate
// in storage is NOT expiring soon. A certificate that is expiring
// soon in our cache but is not expiring soon in storage probably
// means that another instance renewed the certificate in the
// meantime, and it would be a good idea to simply load the cert
// into our cache rather than repeating the renewal process again.
func managedCertInStorageExpiresSoon(cert Certificate) (bool, error) {
	if len(cert.configs) == 0 {
		return false, fmt.Errorf("no configs for certificate")
	}
	storage, err := cert.configs[0].StorageFor(cert.configs[0].CAUrl)
	if err != nil {
		return false, err
	}
	siteData, err := storage.LoadSite(cert.Names[0])
	if err != nil {
		return false, err
	}
	tlsCert, err := tls.X509KeyPair(siteData.Cert, siteData.Key)
	if err != nil {
		return false, err
	}
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return false, err
	}
	timeLeft := leaf.NotAfter.Sub(time.Now().UTC())
	return timeLeft < RenewDurationBefore, nil
}

// cacheCertificate adds cert to the in-memory cache. If a certificate
// with the same hash is already cached, it is NOT overwritten; instead,
// cfg is added to the existing certificate's list of configs if not
// already in the list. Then all the names on cert are used to add
// entries to cfg.Certificates (the config's name lookup map).
// Then the certificate is stored/updated in the cache. It returns
// a copy of the certificate that ends up being stored in the cache.
//
// It is VERY important, even for some test cases, that the Hash field
// of the cert be set properly.
//
// This function is safe for concurrent use.
func (cfg *Config) cacheCertificate(cert Certificate) Certificate {
	cfg.certCache.Lock()
	defer cfg.certCache.Unlock()

	// if this certificate already exists in the cache,
	// use it instead of overwriting it -- very important!
	if existingCert, ok := cfg.certCache.cache[cert.Hash]; ok {
		cert = existingCert
	}

	// attach this config to the certificate so we know which
	// configs are referencing/using the certificate, but don't
	// duplicate entries
	var found bool
	for _, c := range cert.configs {
		if c == cfg {
			found = true
			break
		}
	}
	if !found {
		cert.configs = append(cert.configs, cfg)
	}

	// key the certificate by all its names for this config only,
	// this is how we find the certificate during handshakes
	// (yes, if certs overlap in the names they serve, one will
	// overwrite another here, but that's just how it goes)
	for _, name := range cert.Names {
		cfg.Certificates[name] = cert.Hash
	}

	// store the certificate
	cfg.certCache.cache[cert.Hash] = cert

	return cert
}
