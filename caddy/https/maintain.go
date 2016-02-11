package https

import (
	"log"
	"time"

	"golang.org/x/crypto/ocsp"
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
			updatePreloadedOCSPStaples()
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
				client, err = NewACMEClient("", allowPrompts) // renewals don't use email
				if err != nil {
					return err
				}
				client.Configure("") // TODO: Bind address of relevant listener, yuck
			}

			err := client.Renew(cert.Names[0]) // managed certs better have only one name
			if err != nil {
				if client.AllowPrompts {
					// User is present, so stop immediately and report the error
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

func updatePreloadedOCSPStaples() {
	// Create a temporary place to store updates
	// until we release the potentially slow read
	// lock so we can use a quick write lock.
	type ocspUpdate struct {
		rawBytes       []byte
		parsedResponse *ocsp.Response
	}
	updated := make(map[string]ocspUpdate)

	certCacheMu.RLock()
	for name, cert := range certCache {
		// we update OCSP for managed and un-managed certs here, but only
		// if it has OCSP stapled and only for pre-loaded certificates
		if cert.OnDemand || cert.OCSP == nil {
			continue
		}

		// start checking OCSP staple about halfway through validity period for good measure
		oldNextUpdate := cert.OCSP.NextUpdate
		refreshTime := cert.OCSP.ThisUpdate.Add(oldNextUpdate.Sub(cert.OCSP.ThisUpdate) / 2)

		// only check for updated OCSP validity window if the refresh time is
		// in the past and the certificate is not expired
		if time.Now().After(refreshTime) && time.Now().Before(cert.NotAfter) {
			err := stapleOCSP(&cert, nil)
			if err != nil {
				log.Printf("[ERROR] Checking OCSP for %s: %v", name, err)
				continue
			}

			// if the OCSP response has been updated, we use it
			if oldNextUpdate != cert.OCSP.NextUpdate {
				log.Printf("[INFO] Moving validity period of OCSP staple for %s from %v to %v",
					name, oldNextUpdate, cert.OCSP.NextUpdate)
				updated[name] = ocspUpdate{rawBytes: cert.Certificate.OCSPStaple, parsedResponse: cert.OCSP}
			}
		}
	}
	certCacheMu.RUnlock()

	// This write lock should be brief since we have all the info we need now.
	certCacheMu.Lock()
	for name, update := range updated {
		cert := certCache[name]
		cert.OCSP = update.parsedResponse
		cert.Certificate.OCSPStaple = update.rawBytes
		certCache[name] = cert
	}
	certCacheMu.Unlock()
}

// renewDurationBefore is how long before expiration to renew certificates.
const renewDurationBefore = (24 * time.Hour) * 30
