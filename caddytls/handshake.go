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
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// configGroup is a type that keys configs by their hostname
// (hostnames can have wildcard characters; use the getConfig
// method to get a config by matching its hostname).
type configGroup map[string]*Config

// getConfig gets the config by the first key match for name.
// In other words, "sub.foo.bar" will get the config for "*.foo.bar"
// if that is the closest match. If no match is found, the first
// (random) config will be loaded, which will defer any TLS alerts
// to the certificate validation (this may or may not be ideal;
// let's talk about it if this becomes problematic).
//
// This function follows nearly the same logic to lookup
// a hostname as the getCertificate function uses.
func (cg configGroup) getConfig(name string) *Config {
	name = strings.ToLower(name)

	// exact match? great, let's use it
	if config, ok := cg[name]; ok {
		return config
	}

	// try replacing labels in the name with wildcards until we get a match
	labels := strings.Split(name, ".")
	for i := range labels {
		labels[i] = "*"
		candidate := strings.Join(labels, ".")
		if config, ok := cg[candidate]; ok {
			return config
		}
	}

	// try a config that serves all names (this
	// is basically the same as a config defined
	// for "*" -- I think -- but the above loop
	// doesn't try an empty string)
	if config, ok := cg[""]; ok {
		return config
	}

	// no matches, so just serve up a random config
	for _, config := range cg {
		return config
	}

	return nil
}

// GetConfigForClient gets a TLS configuration satisfying clientHello.
// In getting the configuration, it abides the rules and settings
// defined in the Config that matches clientHello.ServerName. If no
// tls.Config is set on the matching Config, a nil value is returned.
//
// This method is safe for use as a tls.Config.GetConfigForClient callback.
func (cg configGroup) GetConfigForClient(clientHello *tls.ClientHelloInfo) (*tls.Config, error) {
	config := cg.getConfig(clientHello.ServerName)
	if config != nil {
		return config.tlsConfig, nil
	}
	return nil, nil
}

// GetCertificate gets a certificate to satisfy clientHello. In getting
// the certificate, it abides the rules and settings defined in the
// Config that matches clientHello.ServerName. It first checks the in-
// memory cache, then, if the config enables "OnDemand", it accesses
// disk, then accesses the network if it must obtain a new certificate
// via ACME.
//
// This method is safe for use as a tls.Config.GetCertificate callback.
func (cfg *Config) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert, err := cfg.getCertDuringHandshake(strings.ToLower(clientHello.ServerName), true, true)
	return &cert.Certificate, err
}

// getCertificate gets a certificate that matches name (a server name)
// from the in-memory cache, according to the lookup table associated with
// cfg. The lookup then points to a certificate in the Instance certificate
// cache.
//
// If there is no exact match for name, it will be checked against names of
// the form '*.example.com' (wildcard certificates) according to RFC 6125.
// If a match is found, matched will be true. If no matches are found, matched
// will be false and a "default" certificate will be returned with defaulted
// set to true. If defaulted is false, then no certificates were available.
//
// The logic in this function is adapted from the Go standard library,
// which is by the Go Authors.
//
// This function is safe for concurrent use.
func (cfg *Config) getCertificate(name string) (cert Certificate, matched, defaulted bool) {
	var certKey string
	var ok bool

	// Not going to trim trailing dots here since RFC 3546 says,
	// "The hostname is represented ... without a trailing dot."
	// Just normalize to lowercase.
	name = strings.ToLower(name)

	cfg.certCache.RLock()
	defer cfg.certCache.RUnlock()

	// exact match? great, let's use it
	if certKey, ok = cfg.Certificates[name]; ok {
		cert = cfg.certCache.cache[certKey]
		matched = true
		return
	}

	// try replacing labels in the name with wildcards until we get a match
	labels := strings.Split(name, ".")
	for i := range labels {
		labels[i] = "*"
		candidate := strings.Join(labels, ".")
		if certKey, ok = cfg.Certificates[candidate]; ok {
			cert = cfg.certCache.cache[certKey]
			matched = true
			return
		}
	}

	// check the certCache directly to see if the SNI name is
	// already the key of the certificate it wants! this is vital
	// for supporting the TLS-SNI challenge, since the tlsSNISolver
	// just puts the temporary certificate in the instance cache,
	// with no regard for configs; this also means that the SNI
	// can contain the hash of a specific cert (chain) it wants
	// and we will still be able to serve it up
	// (this behavior, by the way, could be controversial as to
	// whether it complies with RFC 6066 about SNI, but I think
	// it does soooo...)
	// NOTE/TODO: TLS-SNI challenge is changing, as of Jan. 2018
	// but what will be different, if it ever returns, is unclear
	if directCert, ok := cfg.certCache.cache[name]; ok {
		cert = directCert
		matched = true
		return
	}

	// if nothing matches and SNI was not provided, use a random
	// certificate; at least there's a chance this older client
	// can connect, and in the future we won't need this provision
	// (if SNI is present, it's probably best to just raise a TLS
	// alert by not serving a certificate)
	if name == "" {
		for _, certKey := range cfg.Certificates {
			defaulted = true
			cert = cfg.certCache.cache[certKey]
			return
		}
	}

	return
}

// getCertDuringHandshake will get a certificate for name. It first tries
// the in-memory cache. If no certificate for name is in the cache, the
// config most closely corresponding to name will be loaded. If that config
// allows it (OnDemand==true) and if loadIfNecessary == true, it goes to disk
// to load it into the cache and serve it. If it's not on disk and if
// obtainIfNecessary == true, the certificate will be obtained from the CA,
// cached, and served. If obtainIfNecessary is true, then loadIfNecessary
// must also be set to true. An error will be returned if and only if no
// certificate is available.
//
// This function is safe for concurrent use.
func (cfg *Config) getCertDuringHandshake(name string, loadIfNecessary, obtainIfNecessary bool) (Certificate, error) {
	// First check our in-memory cache to see if we've already loaded it
	cert, matched, defaulted := cfg.getCertificate(name)
	if matched {
		return cert, nil
	}

	// If OnDemand is enabled, then we might be able to load or
	// obtain a needed certificate
	if cfg.OnDemand && loadIfNecessary {
		// Then check to see if we have one on disk
		loadedCert, err := cfg.CacheManagedCertificate(name)
		if err == nil {
			loadedCert, err = cfg.handshakeMaintenance(name, loadedCert)
			if err != nil {
				log.Printf("[ERROR] Maintaining newly-loaded certificate for %s: %v", name, err)
			}
			return loadedCert, nil
		}
		if obtainIfNecessary {
			// By this point, we need to ask the CA for a certificate

			name = strings.ToLower(name)

			// Make sure the certificate should be obtained based on config
			err := cfg.checkIfCertShouldBeObtained(name)
			if err != nil {
				return Certificate{}, err
			}

			// Name has to qualify for a certificate
			if !HostQualifies(name) {
				return cert, errors.New("hostname '" + name + "' does not qualify for certificate")
			}

			// Obtain certificate from the CA
			return cfg.obtainOnDemandCertificate(name)
		}
	}

	// Fall back to the default certificate if there is one
	if defaulted {
		return cert, nil
	}

	return Certificate{}, fmt.Errorf("no certificate available for %s", name)
}

// checkIfCertShouldBeObtained checks to see if an on-demand tls certificate
// should be obtained for a given domain based upon the config settings.  If
// a non-nil error is returned, do not issue a new certificate for name.
func (cfg *Config) checkIfCertShouldBeObtained(name string) error {
	// If the "ask" URL is defined in the config, use to determine if a
	// cert should obtained
	if cfg.OnDemandState.AskURL != nil {
		return cfg.checkURLForObtainingNewCerts(name)
	}

	// Otherwise use the limit defined by the "max_certs" setting
	return cfg.checkLimitsForObtainingNewCerts(name)
}

func (cfg *Config) checkURLForObtainingNewCerts(name string) error {
	client := http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return errors.New("following http redirects is not allowed")
		},
	}

	// Copy the URL from the config in order to modify it for this request
	askURL := new(url.URL)
	*askURL = *cfg.OnDemandState.AskURL

	query := askURL.Query()
	query.Set("domain", name)
	askURL.RawQuery = query.Encode()

	resp, err := client.Get(askURL.String())
	if err != nil {
		return fmt.Errorf("error checking %v to deterine if certificate for hostname '%s' should be allowed: %v", cfg.OnDemandState.AskURL, name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("certificate for hostname '%s' not allowed, non-2xx status code %d returned from %v", name, resp.StatusCode, cfg.OnDemandState.AskURL)
	}

	return nil
}

// checkLimitsForObtainingNewCerts checks to see if name can be issued right
// now according the maximum count defined in the configuration. If a non-nil
// error is returned, do not issue a new certificate for name.
func (cfg *Config) checkLimitsForObtainingNewCerts(name string) error {
	// User can set hard limit for number of certs for the process to issue
	if cfg.OnDemandState.MaxObtain > 0 &&
		atomic.LoadInt32(&cfg.OnDemandState.ObtainedCount) >= cfg.OnDemandState.MaxObtain {
		return fmt.Errorf("%s: maximum certificates issued (%d)", name, cfg.OnDemandState.MaxObtain)
	}

	// Make sure name hasn't failed a challenge recently
	failedIssuanceMu.RLock()
	when, ok := failedIssuance[name]
	failedIssuanceMu.RUnlock()
	if ok {
		return fmt.Errorf("%s: throttled; refusing to issue cert since last attempt on %s failed", name, when.String())
	}

	// Make sure, if we've issued a few certificates already, that we haven't
	// issued any recently
	lastIssueTimeMu.Lock()
	since := time.Since(lastIssueTime)
	lastIssueTimeMu.Unlock()
	if atomic.LoadInt32(&cfg.OnDemandState.ObtainedCount) >= 10 && since < 10*time.Minute {
		return fmt.Errorf("%s: throttled; last certificate was obtained %v ago", name, since)
	}

	// Good to go 👍
	return nil
}

// obtainOnDemandCertificate obtains a certificate for name for the given
// name. If another goroutine has already started obtaining a cert for
// name, it will wait and use what the other goroutine obtained.
//
// This function is safe for use by multiple concurrent goroutines.
func (cfg *Config) obtainOnDemandCertificate(name string) (Certificate, error) {
	// We must protect this process from happening concurrently, so synchronize.
	obtainCertWaitChansMu.Lock()
	wait, ok := obtainCertWaitChans[name]
	if ok {
		// lucky us -- another goroutine is already obtaining the certificate.
		// wait for it to finish obtaining the cert and then we'll use it.
		obtainCertWaitChansMu.Unlock()
		<-wait
		return cfg.getCertDuringHandshake(name, true, false)
	}

	// looks like it's up to us to do all the work and obtain the cert.
	// make a chan others can wait on if needed
	wait = make(chan struct{})
	obtainCertWaitChans[name] = wait
	obtainCertWaitChansMu.Unlock()

	// obtain the certificate
	log.Printf("[INFO] Obtaining new certificate for %s", name)
	err := cfg.ObtainCert(name, false)

	// immediately unblock anyone waiting for it; doing this in
	// a defer would risk deadlock because of the recursive call
	// to getCertDuringHandshake below when we return!
	obtainCertWaitChansMu.Lock()
	close(wait)
	delete(obtainCertWaitChans, name)
	obtainCertWaitChansMu.Unlock()

	if err != nil {
		// Failed to solve challenge, so don't allow another on-demand
		// issue for this name to be attempted for a little while.
		failedIssuanceMu.Lock()
		failedIssuance[name] = time.Now()
		go func(name string) {
			time.Sleep(5 * time.Minute)
			failedIssuanceMu.Lock()
			delete(failedIssuance, name)
			failedIssuanceMu.Unlock()
		}(name)
		failedIssuanceMu.Unlock()
		return Certificate{}, err
	}

	// Success - update counters and stuff
	atomic.AddInt32(&cfg.OnDemandState.ObtainedCount, 1)
	lastIssueTimeMu.Lock()
	lastIssueTime = time.Now()
	lastIssueTimeMu.Unlock()

	// certificate is already on disk; now just start over to load it and serve it
	return cfg.getCertDuringHandshake(name, true, false)
}

// handshakeMaintenance performs a check on cert for expiration and OCSP
// validity.
//
// This function is safe for use by multiple concurrent goroutines.
func (cfg *Config) handshakeMaintenance(name string, cert Certificate) (Certificate, error) {
	// Check cert expiration
	timeLeft := cert.NotAfter.Sub(time.Now().UTC())
	if timeLeft < RenewDurationBefore {
		log.Printf("[INFO] Certificate for %v expires in %v; attempting renewal", cert.Names, timeLeft)
		return cfg.renewDynamicCertificate(name, cert)
	}

	// Check OCSP staple validity
	if cert.OCSP != nil {
		refreshTime := cert.OCSP.ThisUpdate.Add(cert.OCSP.NextUpdate.Sub(cert.OCSP.ThisUpdate) / 2)
		if time.Now().After(refreshTime) {
			err := stapleOCSP(&cert, nil)
			if err != nil {
				// An error with OCSP stapling is not the end of the world, and in fact, is
				// quite common considering not all certs have issuer URLs that support it.
				log.Printf("[ERROR] Getting OCSP for %s: %v", name, err)
			}
			cfg.certCache.Lock()
			cfg.certCache.cache[cert.Hash] = cert
			cfg.certCache.Unlock()
		}
	}

	return cert, nil
}

// renewDynamicCertificate renews the certificate for name using cfg. It returns the
// certificate to use and an error, if any. name should already be lower-cased before
// calling this function. name is the name obtained directly from the handshake's
// ClientHello.
//
// This function is safe for use by multiple concurrent goroutines.
func (cfg *Config) renewDynamicCertificate(name string, currentCert Certificate) (Certificate, error) {
	obtainCertWaitChansMu.Lock()
	wait, ok := obtainCertWaitChans[name]
	if ok {
		// lucky us -- another goroutine is already renewing the certificate.
		// wait for it to finish, then we'll use the new one.
		obtainCertWaitChansMu.Unlock()
		<-wait
		return cfg.getCertDuringHandshake(name, true, false)
	}

	// looks like it's up to us to do all the work and renew the cert
	wait = make(chan struct{})
	obtainCertWaitChans[name] = wait
	obtainCertWaitChansMu.Unlock()

	// renew and reload the certificate
	log.Printf("[INFO] Renewing certificate for %s", name)
	err := cfg.RenewCert(name, false)
	if err == nil {
		// even though the recursive nature of the dynamic cert loading
		// would just call this function anyway, we do it here to
		// make the replacement as atomic as possible.
		newCert, err := currentCert.configs[0].CacheManagedCertificate(name)
		if err != nil {
			log.Printf("[ERROR] loading renewed certificate for %s: %v", name, err)
		} else {
			// replace the old certificate with the new one
			err = cfg.certCache.replaceCertificate(currentCert, newCert)
			if err != nil {
				log.Printf("[ERROR] Replacing certificate for %s: %v", name, err)
			}
		}
	}

	// immediately unblock anyone waiting for it; doing this in
	// a defer would risk deadlock because of the recursive call
	// to getCertDuringHandshake below when we return!
	obtainCertWaitChansMu.Lock()
	close(wait)
	delete(obtainCertWaitChans, name)
	obtainCertWaitChansMu.Unlock()

	if err != nil {
		return Certificate{}, err
	}

	return cfg.getCertDuringHandshake(name, true, false)
}

// obtainCertWaitChans is used to coordinate obtaining certs for each hostname.
var obtainCertWaitChans = make(map[string]chan struct{})
var obtainCertWaitChansMu sync.Mutex

// failedIssuance is a set of names that we recently failed to get a
// certificate for from the ACME CA. They are removed after some time.
// When a name is in this map, do not issue a certificate for it on-demand.
var failedIssuance = make(map[string]time.Time)
var failedIssuanceMu sync.RWMutex

// lastIssueTime records when we last obtained a certificate successfully.
// If this value is recent, do not make any on-demand certificate requests.
var lastIssueTime time.Time
var lastIssueTimeMu sync.Mutex
