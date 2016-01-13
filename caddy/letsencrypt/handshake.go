package letsencrypt

import (
	"crypto/tls"
	"errors"
	"strings"
	"sync"

	"github.com/mholt/caddy/server"
)

// GetCertificateDuringHandshake is a function that gets a certificate during a TLS handshake.
// It first checks an in-memory cache in case the cert was requested before, then tries to load
// a certificate in the storage folder from disk. If it can't find an existing certificate, it
// will try to obtain one using ACME, which will then be stored on disk and cached in memory.
//
// This function is safe for use by multiple concurrent goroutines.
func GetCertificateDuringHandshake(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// Utility function to help us load a cert from disk and put it in the cache if successful
	loadCertFromDisk := func(domain string) *tls.Certificate {
		cert, err := tls.LoadX509KeyPair(storage.SiteCertFile(domain), storage.SiteKeyFile(domain))
		if err == nil {
			certCacheMu.Lock()
			if len(certCache) < 10000 { // limit size of cache to prevent a ridiculous, unusual kind of attack
				certCache[domain] = &cert
			}
			certCacheMu.Unlock()
			return &cert
		}
		return nil
	}

	// First check our in-memory cache to see if we've already loaded it
	certCacheMu.RLock()
	cert := server.GetCertificateFromCache(clientHello, certCache)
	certCacheMu.RUnlock()
	if cert != nil {
		return cert, nil
	}

	// Then check to see if we already have one on disk; if we do, add it to cache and use it
	name := strings.ToLower(clientHello.ServerName)
	cert = loadCertFromDisk(name)
	if cert != nil {
		return cert, nil
	}

	// Only option left is to get one from LE, but the name has to qualify first
	if !HostQualifies(name) {
		return nil, nil
	}

	// By this point, we need to obtain one from the CA. We must protect this process
	// from happening concurrently, so synchronize.
	obtainCertWaitGroupsMutex.Lock()
	wg, ok := obtainCertWaitGroups[name]
	if ok {
		// lucky us -- another goroutine is already obtaining the certificate.
		// wait for it to finish obtaining the cert and then we'll use it.
		obtainCertWaitGroupsMutex.Unlock()
		wg.Wait()
		return GetCertificateDuringHandshake(clientHello)
	}

	// looks like it's up to us to do all the work and obtain the cert
	wg = new(sync.WaitGroup)
	wg.Add(1)
	obtainCertWaitGroups[name] = wg
	obtainCertWaitGroupsMutex.Unlock()

	// Unblock waiters and delete waitgroup when we return
	defer func() {
		obtainCertWaitGroupsMutex.Lock()
		wg.Done()
		delete(obtainCertWaitGroups, name)
		obtainCertWaitGroupsMutex.Unlock()
	}()

	// obtain cert
	client, err := newClientPort(DefaultEmail, AlternatePort)
	if err != nil {
		return nil, errors.New("error creating client: " + err.Error())
	}
	err = clientObtain(client, []string{name}, false)
	if err != nil {
		return nil, err
	}

	// load certificate into memory and return it
	return loadCertFromDisk(name), nil
}

// obtainCertWaitGroups is used to coordinate obtaining certs for each hostname.
var obtainCertWaitGroups = make(map[string]*sync.WaitGroup)
var obtainCertWaitGroupsMutex sync.Mutex

// certCache stores certificates that have been obtained in memory.
var certCache = make(map[string]*tls.Certificate)
var certCacheMu sync.RWMutex
