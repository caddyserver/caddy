package letsencrypt

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"time"

	"github.com/mholt/caddy/server"
	"github.com/xenolf/lego/acme"
)

// OnChange is a callback function that will be used to restart
// the application or the part of the application that uses
// the certificates maintained by this package. When at least
// one certificate is renewed or an OCSP status changes, this
// function will be called.
var OnChange func() error

// maintainAssets is a permanently-blocking function
// that loops indefinitely and, on a regular schedule, checks
// certificates for expiration and initiates a renewal of certs
// that are expiring soon. It also updates OCSP stapling and
// performs other maintenance of assets.
//
// You must pass in the server configs to maintain and the channel
// which you'll close when maintenance should stop, to allow this
// goroutine to clean up after itself.
func maintainAssets(configs []server.Config, stopChan chan struct{}) {
	renewalTicker := time.NewTicker(renewInterval)
	ocspTicker := time.NewTicker(ocspInterval)

	for {
		select {
		case <-renewalTicker.C:
			if n, errs := renewCertificates(configs); len(errs) > 0 {
				for _, err := range errs {
					log.Printf("[ERROR] cert renewal: %v\n", err)
				}
				if n > 0 && OnChange != nil {
					err := OnChange()
					if err != nil {
						log.Printf("[ERROR] onchange after cert renewal: %v\n", err)
					}
				}
			}
		case <-ocspTicker.C:
			for bundle, oldStatus := range ocspStatus {
				_, newStatus, err := acme.GetOCSPForCert(*bundle)
				if err == nil && newStatus != oldStatus && OnChange != nil {
					log.Printf("[INFO] ocsp status changed from %v to %v\n", oldStatus, newStatus)
					err := OnChange()
					if err != nil {
						log.Printf("[ERROR] onchange after ocsp update: %v\n", err)
					}
					break
				}
			}
		case <-stopChan:
			renewalTicker.Stop()
			ocspTicker.Stop()
			return
		}
	}
}

// renewCertificates loops through all configured site and
// looks for certificates to renew. Nothing is mutated
// through this function. The changes happen directly on disk.
// It returns the number of certificates renewed and any errors
// that occurred. It only performs a renewal if necessary.
func renewCertificates(configs []server.Config) (int, []error) {
	log.Print("[INFO] Processing certificate renewals...")
	var errs []error
	var n int

	for _, cfg := range configs {
		// Host must be TLS-enabled and have assets managed by LE
		if !cfg.TLS.Enabled || !existingCertAndKey(cfg.Host) {
			continue
		}

		// Read the certificate and get the NotAfter time.
		certBytes, err := ioutil.ReadFile(storage.SiteCertFile(cfg.Host))
		if err != nil {
			errs = append(errs, err)
			continue // still have to check other certificates
		}
		expTime, err := acme.GetPEMCertExpiration(certBytes)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		// The time returned from the certificate is always in UTC.
		// So calculate the time left with local time as UTC.
		// Directly convert it to days for the following checks.
		daysLeft := int(expTime.Sub(time.Now().UTC()).Hours() / 24)

		// Renew with a week or less remaining.
		if daysLeft <= 7 {
			log.Printf("[INFO] There are %d days left on the certificate of %s. Trying to renew now.", daysLeft, cfg.Host)
			client, err := newClient(getEmail(cfg))
			if err != nil {
				errs = append(errs, err)
				continue
			}

			// Read metadata
			metaBytes, err := ioutil.ReadFile(storage.SiteMetaFile(cfg.Host))
			if err != nil {
				errs = append(errs, err)
				continue
			}

			privBytes, err := ioutil.ReadFile(storage.SiteKeyFile(cfg.Host))
			if err != nil {
				errs = append(errs, err)
				continue
			}

			var certMeta acme.CertificateResource
			err = json.Unmarshal(metaBytes, &certMeta)
			certMeta.Certificate = certBytes
			certMeta.PrivateKey = privBytes

			// Renew certificate.
			// TODO: revokeOld should be an option in the caddyfile
			// TODO: bundle should be an option in the caddyfile as well :)
			newCertMeta, err := client.RenewCertificate(certMeta, true, true)
			if err != nil {
				time.Sleep(10 * time.Second)
				newCertMeta, err = client.RenewCertificate(certMeta, true, true)
				if err != nil {
					errs = append(errs, err)
					continue
				}
			}

			saveCertsAndKeys([]acme.CertificateResource{newCertMeta})
			n++
		} else if daysLeft <= 14 {
			// Warn on 14 days remaining
			log.Printf("[WARN] There are %d days left on the certificate for %s. Will renew when 7 days remain.\n", daysLeft, cfg.Host)
		}
	}

	return n, errs
}
