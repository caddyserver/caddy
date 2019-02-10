// Copyright 2015 Matthew Holt
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

package certmagic

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"
)

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

	// whether this certificate is under our management
	managed bool
}

// NeedsRenewal returns true if the certificate is
// expiring soon or has expired.
func (c Certificate) NeedsRenewal() bool {
	if c.NotAfter.IsZero() {
		return false
	}
	renewDurationBefore := DefaultRenewDurationBefore
	if len(c.configs) > 0 && c.configs[0].RenewDurationBefore > 0 {
		renewDurationBefore = c.configs[0].RenewDurationBefore
	}
	return time.Until(c.NotAfter) < renewDurationBefore
}

// CacheManagedCertificate loads the certificate for domain into the
// cache, from the TLS storage for managed certificates. It returns a
// copy of the Certificate that was put into the cache.
//
// This is a lower-level method; normally you'll call Manage() instead.
//
// This method is safe for concurrent use.
func (cfg *Config) CacheManagedCertificate(domain string) (Certificate, error) {
	certRes, err := cfg.loadCertResource(domain)
	if err != nil {
		return Certificate{}, err
	}
	cert, err := cfg.makeCertificateWithOCSP(certRes.Certificate, certRes.PrivateKey)
	if err != nil {
		return cert, err
	}
	cert.managed = true
	if cfg.OnEvent != nil {
		cfg.OnEvent("cached_managed_cert", cert.Names)
	}
	return cfg.cacheCertificate(cert), nil
}

// CacheUnmanagedCertificatePEMFile loads a certificate for host using certFile
// and keyFile, which must be in PEM format. It stores the certificate in
// the in-memory cache.
//
// This method is safe for concurrent use.
func (cfg *Config) CacheUnmanagedCertificatePEMFile(certFile, keyFile string) error {
	cert, err := cfg.makeCertificateFromDiskWithOCSP(certFile, keyFile)
	if err != nil {
		return err
	}
	cfg.cacheCertificate(cert)
	if cfg.OnEvent != nil {
		cfg.OnEvent("cached_unmanaged_cert", cert.Names)
	}
	return nil
}

// CacheUnmanagedTLSCertificate adds tlsCert to the certificate cache.
// It staples OCSP if possible.
//
// This method is safe for concurrent use.
func (cfg *Config) CacheUnmanagedTLSCertificate(tlsCert tls.Certificate) error {
	var cert Certificate
	err := fillCertFromLeaf(&cert, tlsCert)
	if err != nil {
		return err
	}
	err = cfg.certCache.stapleOCSP(&cert, nil)
	if err != nil {
		log.Printf("[WARNING] Stapling OCSP: %v", err)
	}
	if cfg.OnEvent != nil {
		cfg.OnEvent("cached_unmanaged_cert", cert.Names)
	}
	cfg.cacheCertificate(cert)
	return nil
}

// CacheUnmanagedCertificatePEMBytes makes a certificate out of the PEM bytes
// of the certificate and key, then caches it in memory.
//
// This method is safe for concurrent use.
func (cfg *Config) CacheUnmanagedCertificatePEMBytes(certBytes, keyBytes []byte) error {
	cert, err := cfg.makeCertificateWithOCSP(certBytes, keyBytes)
	if err != nil {
		return err
	}
	cfg.cacheCertificate(cert)
	if cfg.OnEvent != nil {
		cfg.OnEvent("cached_unmanaged_cert", cert.Names)
	}
	return nil
}

// makeCertificateFromDiskWithOCSP makes a Certificate by loading the
// certificate and key files. It fills out all the fields in
// the certificate except for the Managed and OnDemand flags.
// (It is up to the caller to set those.) It staples OCSP.
func (cfg *Config) makeCertificateFromDiskWithOCSP(certFile, keyFile string) (Certificate, error) {
	certPEMBlock, err := ioutil.ReadFile(certFile)
	if err != nil {
		return Certificate{}, err
	}
	keyPEMBlock, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return Certificate{}, err
	}
	return cfg.makeCertificateWithOCSP(certPEMBlock, keyPEMBlock)
}

// makeCertificate turns a certificate PEM bundle and a key PEM block into
// a Certificate with necessary metadata from parsing its bytes filled into
// its struct fields for convenience (except for the OnDemand and Managed
// flags; it is up to the caller to set those properties!). This function
// does NOT staple OCSP.
func (*Config) makeCertificate(certPEMBlock, keyPEMBlock []byte) (Certificate, error) {
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
func (cfg *Config) makeCertificateWithOCSP(certPEMBlock, keyPEMBlock []byte) (Certificate, error) {
	cert, err := cfg.makeCertificate(certPEMBlock, keyPEMBlock)
	if err != nil {
		return cert, err
	}
	err = cfg.certCache.stapleOCSP(&cert, certPEMBlock)
	if err != nil {
		log.Printf("[WARNING] Stapling OCSP: %v", err)
	}
	return cert, nil
}

// fillCertFromLeaf populates metadata fields on cert from tlsCert.
func fillCertFromLeaf(cert *Certificate, tlsCert tls.Certificate) error {
	if len(tlsCert.Certificate) == 0 {
		return fmt.Errorf("certificate is empty")
	}
	cert.Certificate = tlsCert

	// the leaf cert should be the one for the site; it has what we need
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return err
	}

	if leaf.Subject.CommonName != "" { // TODO: CommonName is deprecated
		cert.Names = []string{strings.ToLower(leaf.Subject.CommonName)}
	}
	for _, name := range leaf.DNSNames {
		if name != leaf.Subject.CommonName { // TODO: CommonName is deprecated
			cert.Names = append(cert.Names, strings.ToLower(name))
		}
	}
	for _, ip := range leaf.IPAddresses {
		if ipStr := ip.String(); ipStr != leaf.Subject.CommonName { // TODO: CommonName is deprecated
			cert.Names = append(cert.Names, strings.ToLower(ipStr))
		}
	}
	for _, email := range leaf.EmailAddresses {
		if email != leaf.Subject.CommonName { // TODO: CommonName is deprecated
			cert.Names = append(cert.Names, strings.ToLower(email))
		}
	}
	if len(cert.Names) == 0 {
		return fmt.Errorf("certificate has no names")
	}

	// save the hash of this certificate (chain) and
	// expiration date, for necessity and efficiency
	cert.Hash = hashCertificateChain(cert.Certificate.Certificate)
	cert.NotAfter = leaf.NotAfter

	return nil
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
	cfg := cert.configs[0]
	certRes, err := cfg.loadCertResource(cert.Names[0])
	if err != nil {
		return false, err
	}
	tlsCert, err := tls.X509KeyPair(certRes.Certificate, certRes.PrivateKey)
	if err != nil {
		return false, err
	}
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return false, err
	}
	timeLeft := leaf.NotAfter.Sub(time.Now().UTC())
	return timeLeft < cfg.RenewDurationBefore, nil
}

// cacheCertificate adds cert to the in-memory cache. If a certificate
// with the same hash is already cached, it is NOT overwritten; instead,
// cfg is added to the existing certificate's list of configs if not
// already in the list. Then all the names on cert are used to add
// entries to cfg.certificates (the config's name lookup map).
// Then the certificate is stored/updated in the cache. It returns
// a copy of the certificate that ends up being stored in the cache.
//
// It is VERY important, even for some test cases, that the Hash field
// of the cert be set properly.
//
// This function is safe for concurrent use.
func (cfg *Config) cacheCertificate(cert Certificate) Certificate {
	cfg.certCache.mu.Lock()
	defer cfg.certCache.mu.Unlock()

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
		cfg.certificates[NormalizedName(name)] = cert.Hash
	}

	// store the certificate
	cfg.certCache.cache[cert.Hash] = cert

	return cert
}

// HostQualifies returns true if the hostname alone
// appears eligible for automagic TLS. For example:
// localhost, empty hostname, and IP addresses are
// not eligible because we cannot obtain certificates
// for those names. Wildcard names are allowed, as long
// as they conform to CABF requirements (only one wildcard
// label, and it must be the left-most label).
func HostQualifies(hostname string) bool {
	return hostname != "localhost" && // localhost is ineligible

		// hostname must not be empty
		strings.TrimSpace(hostname) != "" &&

		// only one wildcard label allowed, and it must be left-most
		(!strings.Contains(hostname, "*") ||
			(strings.Count(hostname, "*") == 1 &&
				strings.HasPrefix(hostname, "*."))) &&

		// must not start or end with a dot
		!strings.HasPrefix(hostname, ".") &&
		!strings.HasSuffix(hostname, ".") &&

		// cannot be an IP address, see
		// https://community.letsencrypt.org/t/certificate-for-static-ip/84/2?u=mholt
		net.ParseIP(hostname) == nil
}
