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
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/mholt/caddy"

	"golang.org/x/crypto/ocsp"
)

func init() {
	// maintain assets while this package is imported, which is
	// always. we don't ever stop it, since we need it running.
	go maintainAssets(make(chan struct{}))
}

const (
	// RenewInterval is how often to check certificates for renewal.
	RenewInterval = 12 * time.Hour

	// RenewDurationBefore is how long before expiration to renew certificates.
	RenewDurationBefore = (24 * time.Hour) * 30

	// RenewDurationBeforeAtStartup is how long before expiration to require
	// a renewed certificate when the process is first starting up (see #1680).
	// A wider window between RenewDurationBefore and this value will allow
	// Caddy to start under duress but hopefully this duration will give it
	// enough time for the blockage to be relieved.
	RenewDurationBeforeAtStartup = (24 * time.Hour) * 7

	// OCSPInterval is how often to check if OCSP stapling needs updating.
	OCSPInterval = 1 * time.Hour
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
func maintainAssets(stopChan chan struct{}) {
	renewalTicker := time.NewTicker(RenewInterval)
	ocspTicker := time.NewTicker(OCSPInterval)

	for {
		select {
		case <-renewalTicker.C:
			log.Println("[INFO] Scanning for expiring certificates")
			RenewManagedCertificates(false)
			log.Println("[INFO] Done checking certificates")
		case <-ocspTicker.C:
			log.Println("[INFO] Scanning for stale OCSP staples")
			UpdateOCSPStaples()
			DeleteOldStapleFiles()
			log.Println("[INFO] Done checking OCSP staples")
		case <-stopChan:
			renewalTicker.Stop()
			ocspTicker.Stop()
			log.Println("[INFO] Stopped background maintenance routine")
			return
		}
	}
}

// RenewManagedCertificates renews managed certificates,
// including ones loaded on-demand.
func RenewManagedCertificates(allowPrompts bool) (err error) {
	for _, inst := range caddy.Instances() {
		inst.StorageMu.RLock()
		certCache, ok := inst.Storage[CertCacheInstStorageKey].(*certificateCache)
		inst.StorageMu.RUnlock()
		if !ok || certCache == nil {
			continue
		}

		// we use the queues for a very important reason: to do any and all
		// operations that could require an exclusive write lock outside
		// of the read lock! otherwise we get a deadlock, yikes. in other
		// words, our first iteration through the certificate cache does NOT
		// perform any operations--only queues them--so that more fine-grained
		// write locks may be obtained during the actual operations.
		var renewQueue, reloadQueue, deleteQueue []Certificate

		certCache.RLock()
		for certKey, cert := range certCache.cache {
			if len(cert.configs) == 0 {
				// this is bad if this happens, probably a programmer error (oops)
				log.Printf("[ERROR] No associated TLS config for certificate with names %v; unable to manage", cert.Names)
				continue
			}
			if !cert.configs[0].Managed || cert.configs[0].SelfSigned {
				continue
			}

			// the list of names on this cert should never be empty... programmer error?
			if cert.Names == nil || len(cert.Names) == 0 {
				log.Printf("[WARNING] Certificate keyed by '%s' has no names: %v - removing from cache", certKey, cert.Names)
				deleteQueue = append(deleteQueue, cert)
				continue
			}

			// if time is up or expires soon, we need to try to renew it
			timeLeft := cert.NotAfter.Sub(time.Now().UTC())
			if timeLeft < RenewDurationBefore {
				// see if the certificate in storage has already been renewed, possibly by another
				// instance of Caddy that didn't coordinate with this one; if so, just load it (this
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
				// NOTE 1: This is not correct 100% of the time, if multiple Caddy instances
				// happen to run their maintenance checks at approximately the same times;
				// both might start renewal at about the same time and do two renewals and one
				// will overwrite the other. Hence TLS storage plugins. This is sort of a TODO.
				// NOTE 2: It is super-important to note that the TLS-SNI challenge requires
				// a write lock on the cache in order to complete its challenge, so it is extra
				// vital that this renew operation does not happen inside our read lock!
				renewQueue = append(renewQueue, cert)
			}
		}
		certCache.RUnlock()

		// Reload certificates that merely need to be updated in memory
		for _, oldCert := range reloadQueue {
			timeLeft := oldCert.NotAfter.Sub(time.Now().UTC())
			log.Printf("[INFO] Certificate for %v expires in %v, but is already renewed in storage; reloading stored certificate",
				oldCert.Names, timeLeft)

			err = certCache.reloadManagedCertificate(oldCert)
			if err != nil {
				if allowPrompts {
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
			// so this should be easy. We can't rely on cert.Config.Hostname
			// because it may be a wildcard value from the Caddyfile (e.g.
			// *.something.com) which, as of Jan. 2017, is not supported by ACME.
			// TODO: ^ ^ ^ (wildcards)
			renewName := oldCert.Names[0]

			// perform renewal
			err := oldCert.configs[0].RenewCert(renewName, allowPrompts)
			if err != nil {
				if allowPrompts {
					// Certificate renewal failed and the operator is present. See a discussion
					// about this in issue 642. For a while, we only stopped if the certificate
					// was expired, but in reality, there is no difference between reporting
					// it now versus later, except that there's somebody present to deal with
					// it right now. Follow-up: See issue 1680. Only fail in this case if the
					// certificate is dangerously close to expiration.
					timeLeft := oldCert.NotAfter.Sub(time.Now().UTC())
					if timeLeft < RenewDurationBeforeAtStartup {
						return err
					}
				}
				log.Printf("[ERROR] %v", err)
				if oldCert.configs[0].OnDemand {
					// loaded dynamically, remove dynamically
					deleteQueue = append(deleteQueue, oldCert)
				}
				continue
			}

			// successful renewal, so update in-memory cache by loading
			// renewed certificate so it will be used with handshakes
			err = certCache.reloadManagedCertificate(oldCert)
			if err != nil {
				if allowPrompts {
					return err // operator is present, so report error immediately
				}
				log.Printf("[ERROR] %v", err)
			}
		}

		// Deletion queue
		for _, cert := range deleteQueue {
			certCache.Lock()
			// remove any pointers to this certificate from Configs
			for _, cfg := range cert.configs {
				for name, certKey := range cfg.Certificates {
					if certKey == cert.Hash {
						delete(cfg.Certificates, name)
					}
				}
			}
			// then delete the certificate from the cache
			delete(certCache.cache, cert.Hash)
			certCache.Unlock()
		}
	}

	return nil
}

// UpdateOCSPStaples updates the OCSP stapling in all
// eligible, cached certificates.
//
// OCSP maintenance strives to abide the relevant points on
// Ryan Sleevi's recommendations for good OCSP support:
// https://gist.github.com/sleevi/5efe9ef98961ecfb4da8
func UpdateOCSPStaples() {
	for _, inst := range caddy.Instances() {
		inst.StorageMu.RLock()
		certCache, ok := inst.Storage[CertCacheInstStorageKey].(*certificateCache)
		inst.StorageMu.RUnlock()
		if !ok || certCache == nil {
			continue
		}

		// Create a temporary place to store updates
		// until we release the potentially long-lived
		// read lock and use a short-lived write lock
		// on the certificate cache.
		type ocspUpdate struct {
			rawBytes []byte
			parsed   *ocsp.Response
		}
		updated := make(map[string]ocspUpdate)

		certCache.RLock()
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

			err := stapleOCSP(&cert, nil)
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
		certCache.RUnlock()

		// These write locks should be brief since we have all the info we need now.
		for certKey, update := range updated {
			certCache.Lock()
			cert := certCache.cache[certKey]
			cert.OCSP = update.parsed
			cert.Certificate.OCSPStaple = update.rawBytes
			certCache.cache[certKey] = cert
			certCache.Unlock()
		}
	}
}

// DeleteOldStapleFiles deletes cached OCSP staples that have expired.
// TODO: Should we do this for certificates too?
func DeleteOldStapleFiles() {
	// TODO: Upgrade caddytls.Storage to support OCSP operations too
	files, err := ioutil.ReadDir(ocspFolder)
	if err != nil {
		// maybe just hasn't been created yet; no big deal
		return
	}
	for _, file := range files {
		if file.IsDir() {
			// weird, what's a folder doing inside the OCSP cache?
			continue
		}
		stapleFile := filepath.Join(ocspFolder, file.Name())
		ocspBytes, err := ioutil.ReadFile(stapleFile)
		if err != nil {
			continue
		}
		resp, err := ocsp.ParseResponse(ocspBytes, nil)
		if err != nil {
			// contents are invalid; delete it
			err = os.Remove(stapleFile)
			if err != nil {
				log.Printf("[ERROR] Purging corrupt staple file %s: %v", stapleFile, err)
			}
			continue
		}
		if time.Now().After(resp.NextUpdate) {
			// response has expired; delete it
			err = os.Remove(stapleFile)
			if err != nil {
				log.Printf("[ERROR] Purging expired staple file %s: %v", stapleFile, err)
			}
		}
	}
}

// freshOCSP returns true if resp is still fresh,
// meaning that it is not expedient to get an
// updated response from the OCSP server.
func freshOCSP(resp *ocsp.Response) bool {
	nextUpdate := resp.NextUpdate
	// If there is an OCSP responder certificate, and it expires before the
	// OCSP response, use its expiration date as the end of the OCSP
	// response's validity period.
	if resp.Certificate != nil && resp.Certificate.NotAfter.Before(nextUpdate) {
		nextUpdate = resp.Certificate.NotAfter
	}
	// start checking OCSP staple about halfway through validity period for good measure
	refreshTime := resp.ThisUpdate.Add(nextUpdate.Sub(resp.ThisUpdate) / 2)
	return time.Now().Before(refreshTime)
}

var ocspFolder = filepath.Join(caddy.AssetsPath(), "ocsp")
