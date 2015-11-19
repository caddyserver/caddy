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
// goroutine to clean up after itself and unblock.
func maintainAssets(configs []server.Config, stopChan chan struct{}) {
	renewalTicker := time.NewTicker(renewInterval)
	ocspTicker := time.NewTicker(ocspInterval)

	for {
		select {
		case <-renewalTicker.C:
			n, errs := renewCertificates(configs, true)
			if len(errs) > 0 {
				for _, err := range errs {
					log.Printf("[ERROR] Certificate renewal: %v", err)
				}
			}
			// even if there was an error, some renewals may have succeeded
			if n > 0 && OnChange != nil {
				err := OnChange()
				if err != nil {
					log.Printf("[ERROR] OnChange after cert renewal: %v", err)
				}
			}
		case <-ocspTicker.C:
			for bundle, oldStatus := range ocspStatus {
				_, newStatus, err := acme.GetOCSPForCert(*bundle)
				if err == nil && newStatus != oldStatus && OnChange != nil {
					log.Printf("[INFO] OCSP status changed from %v to %v", oldStatus, newStatus)
					err := OnChange()
					if err != nil {
						log.Printf("[ERROR] OnChange after OCSP update: %v", err)
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
// through this function; all changes happen directly on disk.
// It returns the number of certificates renewed and any errors
// that occurred. It only performs a renewal if necessary.
// If useCustomPort is true, a custom port will be used, and
// whatever is listening at 443 better proxy ACME requests to it.
// Otherwise, the acme package will create its own listener on 443.
func renewCertificates(configs []server.Config, useCustomPort bool) (int, []error) {
	log.Printf("[INFO] Checking certificates for %d hosts", len(configs))
	var errs []error
	var n int

	for _, cfg := range configs {
		// Host must be TLS-enabled and have existing assets managed by LE
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

		// Renew with two weeks or less remaining.
		if daysLeft <= 14 {
			log.Printf("[INFO] Certificate for %s has %d days remaining; attempting renewal", cfg.Host, daysLeft)
			var client *acme.Client
			if useCustomPort {
				client, err = newClientPort("", alternatePort) // email not used for renewal
			} else {
				client, err = newClient("")
			}
			if err != nil {
				errs = append(errs, err)
				continue
			}

			// Read and set up cert meta, required for renewal
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

			// Renew certificate
		Renew:
			newCertMeta, err := client.RenewCertificate(certMeta, true, true)
			if err != nil {
				if _, ok := err.(acme.TOSError); ok {
					err := client.AgreeToTOS()
					if err != nil {
						errs = append(errs, err)
					}
					goto Renew
				}

				time.Sleep(10 * time.Second)
				newCertMeta, err = client.RenewCertificate(certMeta, true, true)
				if err != nil {
					errs = append(errs, err)
					continue
				}
			}

			saveCertsAndKeys([]acme.CertificateResource{newCertMeta})
			n++
		} else if daysLeft <= 30 {
			// Warn on 30 days remaining. TODO: Just do this once...
			log.Printf("[WARNING] Certificate for %s has %d days remaining; will automatically renew when 14 days remain\n", cfg.Host, daysLeft)
		}
	}

	return n, errs
}

// acmeHandlers is a map of host to ACME handler. These
// are used to proxy ACME requests to the ACME client.
var acmeHandlers = make(map[string]*Handler)
