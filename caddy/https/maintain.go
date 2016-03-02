package https

import (
	"log"
	"time"

	"github.com/mholt/caddy/server"

	"golang.org/x/crypto/ocsp"
)

const (
	// RenewInterval is how often to check certificates for renewal.
	RenewInterval = 12 * time.Hour

	// OCSPInterval is how often to check if OCSP stapling needs updating.
	OCSPInterval = 1 * time.Hour
)

// maintainAssets is a permanently-blocking function
// that loops indefinitely and, on a regular schedule, checks
// certificates for expiration and initiates a renewal of certs
// that are expiring soon. It also updates OCSP stapling and
// performs other maintenance of assets.
//
// You must pass in the channel which you'll close when
// maintenance should stop, to allow this goroutine to clean up
// after itself and unblock.
func maintainAssets(stopChan chan struct{}) {
	renewalTicker := time.NewTicker(RenewInterval)
	ocspTicker := time.NewTicker(OCSPInterval)

	for {
		select {
		case <-renewalTicker.C:
			log.Println("[INFO] Scanning for expiring certificates")
			renewManagedCertificates(false)
			log.Println("[INFO] Done checking certificates")
		case <-ocspTicker.C:
			log.Println("[INFO] Scanning for stale OCSP staples")
			updateOCSPStaples()
			log.Println("[INFO] Done checking OCSP staples")
		case <-stopChan:
			renewalTicker.Stop()
			ocspTicker.Stop()
			log.Println("[INFO] Stopped background maintenance routine")
			return
		}
	}
}

func renewManagedCertificates(allowPrompts bool) (err error) {
	var renewed, deleted []Certificate
	var client *ACMEClient
	visitedNames := make(map[string]struct{})

	certCacheMu.RLock()
	for name, cert := range certCache {
		if !cert.Managed {
			continue
		}

		// the list of names on this cert should never be empty...
		if cert.Names == nil || len(cert.Names) == 0 {
			log.Printf("[WARNING] Certificate keyed by '%s' has no names: %v", name, cert.Names)
			deleted = append(deleted, cert)
			continue
		}

		// skip names whose certificate we've already renewed
		if _, ok := visitedNames[name]; ok {
			continue
		}
		for _, name := range cert.Names {
			visitedNames[name] = struct{}{}
		}

		timeLeft := cert.NotAfter.Sub(time.Now().UTC())
		if timeLeft < renewDurationBefore {
			log.Printf("[INFO] Certificate for %v expires in %v; attempting renewal", cert.Names, timeLeft)

			if client == nil {
				client, err = NewACMEClientGetEmail(server.Config{}, allowPrompts)
				if err != nil {
					return err
				}
				client.Configure("") // TODO: Bind address of relevant listener, yuck
			}

			err := client.Renew(cert.Names[0]) // managed certs better have only one name
			if err != nil {
				if client.AllowPrompts && timeLeft < 0 {
					// Certificate renewal failed, the operator is present, and the certificate
					// is already expired; we should stop immediately and return the error. Note
					// that we used to do this any time a renewal failed at startup. However,
					// after discussion in https://github.com/mholt/caddy/issues/642 we decided to
					// only stop startup if the certificate is expired. We still log the error
					// otherwise.
					certCacheMu.RUnlock()
					return err
				}
				log.Printf("[ERROR] %v", err)
				if cert.OnDemand {
					deleted = append(deleted, cert)
				}
			} else {
				renewed = append(renewed, cert)
			}
		}
	}
	certCacheMu.RUnlock()

	// Apply changes to the cache
	for _, cert := range renewed {
		_, err := cacheManagedCertificate(cert.Names[0], cert.OnDemand)
		if err != nil {
			if client.AllowPrompts {
				return err // operator is present, so report error immediately
			}
			log.Printf("[ERROR] %v", err)
		}
	}
	for _, cert := range deleted {
		certCacheMu.Lock()
		for _, name := range cert.Names {
			delete(certCache, name)
		}
		certCacheMu.Unlock()
	}

	return nil
}

func updateOCSPStaples() {
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
			// start checking OCSP staple about halfway through validity period for good measure
			lastNextUpdate = cert.OCSP.NextUpdate
			refreshTime := cert.OCSP.ThisUpdate.Add(lastNextUpdate.Sub(cert.OCSP.ThisUpdate) / 2)

			// since OCSP is already stapled, we need only check if we're in that "refresh window"
			if time.Now().Before(refreshTime) {
				continue
			}
		}

		err := stapleOCSP(&cert, nil)
		if err != nil {
			if cert.OCSP != nil {
				// if it was no staple before, that's fine, otherwise we should log the error
				log.Printf("[ERROR] Checking OCSP for %s: %v", name, err)
			}
			continue
		}

		// By this point, we've obtained the latest OCSP response.
		// If there was no staple before, or if the response is updated, make
		// sure we apply the update to all names on the certificate.
		if lastNextUpdate.IsZero() || lastNextUpdate != cert.OCSP.NextUpdate {
			log.Printf("[INFO] Advancing OCSP staple for %v from %s to %s",
				cert.Names, lastNextUpdate, cert.OCSP.NextUpdate)
			for _, n := range cert.Names {
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

// renewDurationBefore is how long before expiration to renew certificates.
const renewDurationBefore = (24 * time.Hour) * 30
