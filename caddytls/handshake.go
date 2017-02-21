package caddytls

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
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

	// as a fallback, try a config that serves all names
	if config, ok := cg[""]; ok {
		return config
	}

	// as a last resort, use a random config
	// (even if the config isn't for that hostname,
	// it should help us serve clients without SNI
	// or at least defer TLS alerts to the cert)
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
	cert, matched, defaulted := getCertificate(name)
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

			// Make sure aren't over any applicable limits
			err := cfg.checkLimitsForObtainingNewCerts(name)
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

// checkLimitsForObtainingNewCerts checks to see if name can be issued right
// now according to mitigating factors we keep track of and preferences the
// user has set. If a non-nil error is returned, do not issue a new certificate
// for name.
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

	// do the obtain
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
		return cfg.renewDynamicCertificate(name)
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
			certCacheMu.Lock()
			certCache[name] = cert
			certCacheMu.Unlock()
		}
	}

	return cert, nil
}

// renewDynamicCertificate renews the certificate for name using cfg. It returns the
// certificate to use and an error, if any. currentCert may be returned even if an
// error occurs, since we perform renewals before they expire and it may still be
// usable. name should already be lower-cased before calling this function.
//
// This function is safe for use by multiple concurrent goroutines.
func (cfg *Config) renewDynamicCertificate(name string) (Certificate, error) {
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

	// do the renew
	log.Printf("[INFO] Renewing certificate for %s", name)
	err := cfg.RenewCert(name, false)

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
