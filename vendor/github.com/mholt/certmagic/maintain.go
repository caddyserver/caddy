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
	"log"
	"time"

	"golang.org/x/crypto/ocsp"
)

// maintainAssets is a permanently-blocking function
// that loops indefinitely and, on a regular schedule, checks
// certificates for expiration and initiates a renewal of certs
// that are expiring soon. It also updates OCSP stapling and
// performs other maintenance of assets. It should only be
// called once per process.
//
// You must pass in the channel which you'll close when
// maintenance should stop, to allow this goroutine to clean up
// after itself and unblock. (Not that you HAVE to stop it...)
func (certCache *Cache) maintainAssets() {
	renewalTicker := time.NewTicker(certCache.RenewInterval)
	ocspTicker := time.NewTicker(certCache.OCSPInterval)

	log.Printf("[INFO][%s] Started certificate maintenance routine", certCache.storage)

	for {
		select {
		case <-renewalTicker.C:
			log.Printf("[INFO][%s] Scanning for expiring certificates", certCache.storage)
			err := certCache.RenewManagedCertificates(false)
			if err != nil {
				log.Printf("[ERROR][%s] Renewing managed certificates: %v", certCache.storage, err)
			}
			log.Printf("[INFO][%s] Done scanning certificates", certCache.storage)
		case <-ocspTicker.C:
			log.Printf("[INFO][%s] Scanning for stale OCSP staples", certCache.storage)
			certCache.updateOCSPStaples()
			certCache.deleteOldStapleFiles()
			log.Printf("[INFO][%s] Done checking OCSP staples", certCache.storage)
		case <-certCache.stopChan:
			renewalTicker.Stop()
			ocspTicker.Stop()
			log.Printf("[INFO][%s] Stopped certificate maintenance routine", certCache.storage)
			return
		}
	}
}

// RenewManagedCertificates renews managed certificates,
// including ones loaded on-demand. Note that this is done
// automatically on a regular basis; normally you will not
// need to call this.
func (certCache *Cache) RenewManagedCertificates(interactive bool) error {
	// we use the queues for a very important reason: to do any and all
	// operations that could require an exclusive write lock outside
	// of the read lock! otherwise we get a deadlock, yikes. in other
	// words, our first iteration through the certificate cache does NOT
	// perform any operations--only queues them--so that more fine-grained
	// write locks may be obtained during the actual operations.
	var renewQueue, reloadQueue, deleteQueue []Certificate

	certCache.mu.RLock()
	for certKey, cert := range certCache.cache {
		if len(cert.configs) == 0 {
			// this is bad if this happens, probably a programmer error (oops)
			log.Printf("[ERROR] No associated TLS config for certificate with names %v; unable to manage", cert.Names)
			continue
		}
		if !cert.managed {
			continue
		}

		// the list of names on this cert should never be empty... programmer error?
		if cert.Names == nil || len(cert.Names) == 0 {
			log.Printf("[WARNING] Certificate keyed by '%s' has no names: %v - removing from cache", certKey, cert.Names)
			deleteQueue = append(deleteQueue, cert)
			continue
		}

		// if time is up or expires soon, we need to try to renew it
		if cert.NeedsRenewal() {
			// see if the certificate in storage has already been renewed, possibly by another
			// instance that didn't coordinate with this one; if so, just load it (this
			// might happen if another instance already renewed it - kinda sloppy but checking disk
			// first is a simple way to possibly drastically reduce rate limit problems)
			storedCertExpiring, err := managedCertInStorageExpiresSoon(cert)
			if err != nil {
				// hmm, weird, but not a big deal, maybe it was deleted or something
				log.Printf("[NOTICE] Error while checking if certificate for %v in storage is also expiring soon: %v",
					cert.Names, err)
			} else if !storedCertExpiring {
				// if the certificate is NOT expiring soon and there was no error, then we
				// are good to just reload the certificate from storage instead of repeating
				// a likely-unnecessary renewal procedure
				reloadQueue = append(reloadQueue, cert)
				continue
			}

			// the certificate in storage has not been renewed yet, so we will do it
			// NOTE: It is super-important to note that the TLS-ALPN challenge requires
			// a write lock on the cache in order to complete its challenge, so it is extra
			// vital that this renew operation does not happen inside our read lock!
			renewQueue = append(renewQueue, cert)
		}
	}
	certCache.mu.RUnlock()

	// Reload certificates that merely need to be updated in memory
	for _, oldCert := range reloadQueue {
		timeLeft := oldCert.NotAfter.Sub(time.Now().UTC())
		log.Printf("[INFO] Certificate for %v expires in %v, but is already renewed in storage; reloading stored certificate",
			oldCert.Names, timeLeft)

		err := certCache.reloadManagedCertificate(oldCert)
		if err != nil {
			if interactive {
				return err // operator is present, so report error immediately
			}
			log.Printf("[ERROR] Loading renewed certificate: %v", err)
		}
	}

	// Renewal queue
	for _, oldCert := range renewQueue {
		timeLeft := oldCert.NotAfter.Sub(time.Now().UTC())
		log.Printf("[INFO] Certificate for %v expires in %v; attempting renewal", oldCert.Names, timeLeft)

		// Get the name which we should use to renew this certificate;
		// we only support managing certificates with one name per cert,
		// so this should be easy.
		renewName := oldCert.Names[0]

		// perform renewal
		err := oldCert.configs[0].RenewCert(renewName, interactive)
		if err != nil {
			if interactive {
				// Certificate renewal failed and the operator is present. See a discussion about
				// this in issue mholt/caddy#642. For a while, we only stopped if the certificate
				// was expired, but in reality, there is no difference between reporting it now
				// versus later, except that there's somebody present to deal withit right now.
				// Follow-up: See issue mholt/caddy#1680. Only fail in this case if the certificate
				// is dangerously close to expiration.
				timeLeft := oldCert.NotAfter.Sub(time.Now().UTC())
				if timeLeft < oldCert.configs[0].RenewDurationBeforeAtStartup {
					return err
				}
			}
			log.Printf("[ERROR] %v", err)
			if oldCert.configs[0].OnDemand != nil {
				// loaded dynamically, remove dynamically
				deleteQueue = append(deleteQueue, oldCert)
			}
			continue
		}

		// successful renewal, so update in-memory cache by loading
		// renewed certificate so it will be used with handshakes
		err = certCache.reloadManagedCertificate(oldCert)
		if err != nil {
			if interactive {
				return err // operator is present, so report error immediately
			}
			log.Printf("[ERROR] %v", err)
		}
	}

	// Deletion queue
	for _, cert := range deleteQueue {
		certCache.mu.Lock()
		// remove any pointers to this certificate from Configs
		for _, cfg := range cert.configs {
			for name, certKey := range cfg.certificates {
				if certKey == cert.Hash {
					delete(cfg.certificates, name)
				}
			}
		}
		// then delete the certificate from the cache
		delete(certCache.cache, cert.Hash)
		certCache.mu.Unlock()
	}

	return nil
}

// updateOCSPStaples updates the OCSP stapling in all
// eligible, cached certificates.
//
// OCSP maintenance strives to abide the relevant points on
// Ryan Sleevi's recommendations for good OCSP support:
// https://gist.github.com/sleevi/5efe9ef98961ecfb4da8
func (certCache *Cache) updateOCSPStaples() {
	// Create a temporary place to store updates
	// until we release the potentially long-lived
	// read lock and use a short-lived write lock
	// on the certificate cache.
	type ocspUpdate struct {
		rawBytes []byte
		parsed   *ocsp.Response
	}
	updated := make(map[string]ocspUpdate)

	certCache.mu.RLock()
	for certHash, cert := range certCache.cache {
		// no point in updating OCSP for expired certificates
		if time.Now().After(cert.NotAfter) {
			continue
		}

		var lastNextUpdate time.Time
		if cert.OCSP != nil {
			lastNextUpdate = cert.OCSP.NextUpdate
			if freshOCSP(cert.OCSP) {
				continue // no need to update staple if ours is still fresh
			}
		}

		err := certCache.stapleOCSP(&cert, nil)
		if err != nil {
			if cert.OCSP != nil {
				// if there was no staple before, that's fine; otherwise we should log the error
				log.Printf("[ERROR] Checking OCSP: %v", err)
			}
			continue
		}

		// By this point, we've obtained the latest OCSP response.
		// If there was no staple before, or if the response is updated, make
		// sure we apply the update to all names on the certificate.
		if cert.OCSP != nil && (lastNextUpdate.IsZero() || lastNextUpdate != cert.OCSP.NextUpdate) {
			log.Printf("[INFO] Advancing OCSP staple for %v from %s to %s",
				cert.Names, lastNextUpdate, cert.OCSP.NextUpdate)
			updated[certHash] = ocspUpdate{rawBytes: cert.Certificate.OCSPStaple, parsed: cert.OCSP}
		}
	}
	certCache.mu.RUnlock()

	// These write locks should be brief since we have all the info we need now.
	for certKey, update := range updated {
		certCache.mu.Lock()
		cert := certCache.cache[certKey]
		cert.OCSP = update.parsed
		cert.Certificate.OCSPStaple = update.rawBytes
		certCache.cache[certKey] = cert
		certCache.mu.Unlock()
	}
}

// deleteOldStapleFiles deletes cached OCSP staples that have expired.
// TODO: We should do this for long-expired certificates, too.
func (certCache *Cache) deleteOldStapleFiles() {
	ocspKeys, err := certCache.storage.List(prefixOCSP, false)
	if err != nil {
		// maybe just hasn't been created yet; no big deal
		return
	}
	for _, key := range ocspKeys {
		ocspBytes, err := certCache.storage.Load(key)
		if err != nil {
			log.Printf("[ERROR] While deleting old OCSP staples, unable to load staple file: %v", err)
			continue
		}
		resp, err := ocsp.ParseResponse(ocspBytes, nil)
		if err != nil {
			// contents are invalid; delete it
			err = certCache.storage.Delete(key)
			if err != nil {
				log.Printf("[ERROR] Purging corrupt staple file %s: %v", key, err)
			}
			continue
		}
		if time.Now().After(resp.NextUpdate) {
			// response has expired; delete it
			err = certCache.storage.Delete(key)
			if err != nil {
				log.Printf("[ERROR] Purging expired staple file %s: %v", key, err)
			}
		}
	}
}

const (
	// DefaultRenewInterval is how often to check certificates for renewal.
	DefaultRenewInterval = 12 * time.Hour

	// DefaultRenewDurationBefore is how long before expiration to renew certificates.
	DefaultRenewDurationBefore = (24 * time.Hour) * 30

	// DefaultRenewDurationBeforeAtStartup is how long before expiration to require
	// a renewed certificate when the process is first starting up (see mholt/caddy#1680).
	DefaultRenewDurationBeforeAtStartup = (24 * time.Hour) * 7

	// DefaultOCSPInterval is how often to check if OCSP stapling needs updating.
	DefaultOCSPInterval = 1 * time.Hour
)
