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

// RenewManagedCertificates renews managed certificates.
func RenewManagedCertificates(allowPrompts bool) (err error) {
	var renewQueue, deleteQueue []Certificate
	visitedNames := make(map[string]struct{})

	certCacheMu.RLock()
	for name, cert := range certCache {
		if !cert.Config.Managed || cert.Config.SelfSigned {
			continue
		}

		// the list of names on this cert should never be empty...
		if cert.Names == nil || len(cert.Names) == 0 {
			log.Printf("[WARNING] Certificate keyed by '%s' has no names: %v - removing from cache", name, cert.Names)
			deleteQueue = append(deleteQueue, cert)
			continue
		}

		// skip names whose certificate we've already renewed
		if _, ok := visitedNames[name]; ok {
			continue
		}
		for _, name := range cert.Names {
			visitedNames[name] = struct{}{}
		}

		// if its time is up or ending soon, we need to try to renew it
		timeLeft := cert.NotAfter.Sub(time.Now().UTC())
		if timeLeft < RenewDurationBefore {
			log.Printf("[INFO] Certificate for %v expires in %v; attempting renewal", cert.Names, timeLeft)

			if cert.Config == nil {
				log.Printf("[ERROR] %s: No associated TLS config; unable to renew", name)
				continue
			}

			// queue for renewal when we aren't in a read lock anymore
			// (the TLS-SNI challenge will need a write lock in order to
			// present the certificate, so we renew outside of read lock)
			renewQueue = append(renewQueue, cert)
		}
	}
	certCacheMu.RUnlock()

	// Perform renewals that are queued
	for _, cert := range renewQueue {
		// Get the name which we should use to renew this certificate;
		// we only support managing certificates with one name per cert,
		// so this should be easy. We can't rely on cert.Config.Hostname
		// because it may be a wildcard value from the Caddyfile (e.g.
		// *.something.com) which, as of Jan. 2017, is not supported by ACME.
		var renewName string
		for _, name := range cert.Names {
			if name != "" {
				renewName = name
				break
			}
		}

		// perform renewal
		err := cert.Config.RenewCert(renewName, allowPrompts)
		if err != nil {
			if allowPrompts {
				// Certificate renewal failed and the operator is present. See a discussion
				// about this in issue 642. For a while, we only stopped if the certificate
				// was expired, but in reality, there is no difference between reporting
				// it now versus later, except that there's somebody present to deal with
				// it right now.
				timeLeft := cert.NotAfter.Sub(time.Now().UTC())
				if timeLeft < RenewDurationBeforeAtStartup {
					// See issue 1680. Only fail at startup if the certificate is dangerously
					// close to expiration.
					return err
				}
			}
			log.Printf("[ERROR] %v", err)
			if cert.Config.OnDemand {
				deleteQueue = append(deleteQueue, cert)
			}
		} else {
			// successful renewal, so update in-memory cache by loading
			// renewed certificate so it will be used with handshakes
			if cert.Names[len(cert.Names)-1] == "" {
				// Special case: This is the default certificate. We must
				// flush it out of the cache so that we no longer point to
				// the old, un-renewed certificate. Otherwise it will be
				// renewed on every scan, which is too often. The next cert
				// to be cached (probably this one) will become the default.
				certCacheMu.Lock()
				delete(certCache, "")
				certCacheMu.Unlock()
			}
			_, err := cert.Config.CacheManagedCertificate(cert.Names[0])
			if err != nil {
				if allowPrompts {
					return err // operator is present, so report error immediately
				}
				log.Printf("[ERROR] %v", err)
			}
		}
	}

	// Apply queued deletion changes to the cache
	for _, cert := range deleteQueue {
		certCacheMu.Lock()
		for _, name := range cert.Names {
			delete(certCache, name)
		}
		certCacheMu.Unlock()
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
	// Create a temporary place to store updates
	// until we release the potentially long-lived
	// read lock and use a short-lived write lock.
	type ocspUpdate struct {
		rawBytes []byte
		parsed   *ocsp.Response
	}
	updated := make(map[string]ocspUpdate)

	// A single SAN certificate maps to multiple names, so we use this
	// set to make sure we don't waste cycles checking OCSP for the same
	// certificate multiple times.
	visited := make(map[string]struct{})

	certCacheMu.RLock()
	for name, cert := range certCache {
		// skip this certificate if we've already visited it,
		// and if not, mark all the names as visited
		if _, ok := visited[name]; ok {
			continue
		}
		for _, n := range cert.Names {
			visited[n] = struct{}{}
		}

		// no point in updating OCSP for expired certificates
		if time.Now().After(cert.NotAfter) {
			continue
		}

		var lastNextUpdate time.Time
		if cert.OCSP != nil {
			lastNextUpdate = cert.OCSP.NextUpdate
			if freshOCSP(cert.OCSP) {
				// no need to update staple if ours is still fresh
				continue
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
			for _, n := range cert.Names {
				// BUG: If this certificate has names on it that appear on another
				// certificate in the cache, AND the other certificate is keyed by
				// that name in the cache, then this method of 'queueing' the staple
				// update will cause this certificate's new OCSP to be stapled to
				// a different certificate! See:
				// https://caddy.community/t/random-ocsp-response-errors-for-random-clients/2473?u=matt
				// This problem should be avoided if names on certificates in the
				// cache don't overlap with regards to the cache keys.
				// (This is isn't a bug anymore, since we're careful when we add
				// certificates to the cache by skipping keying when key already exists.)
				updated[n] = ocspUpdate{rawBytes: cert.Certificate.OCSPStaple, parsed: cert.OCSP}
			}
		}
	}
	certCacheMu.RUnlock()

	// This write lock should be brief since we have all the info we need now.
	certCacheMu.Lock()
	for name, update := range updated {
		cert := certCache[name]
		cert.OCSP = update.parsed
		cert.Certificate.OCSPStaple = update.rawBytes
		certCache[name] = cert
	}
	certCacheMu.Unlock()
}

// DeleteOldStapleFiles deletes cached OCSP staples that have expired.
// TODO: Should we do this for certificates too?
func DeleteOldStapleFiles() {
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
	// start checking OCSP staple about halfway through validity period for good measure
	refreshTime := resp.ThisUpdate.Add(resp.NextUpdate.Sub(resp.ThisUpdate) / 2)
	return time.Now().Before(refreshTime)
}

var ocspFolder = filepath.Join(caddy.AssetsPath(), "ocsp")
