package letsencrypt

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"time"

	"github.com/mholt/caddy/server"
	"github.com/xenolf/lego/acme"
)

// keepCertificatesRenewed is a permanently-blocking function
// that loops indefinitely and, on a regular schedule, checks
// certificates for expiration and initiates a renewal of certs
// that are expiring soon.
func keepCertificatesRenewed(configs []server.Config) {
	ticker := time.Tick(renewInterval)
	for range ticker {
		if n, errs := processCertificateRenewal(configs); len(errs) > 0 {
			for _, err := range errs {
				log.Printf("[ERROR] cert renewal: %v\n", err)
			}
			if n > 0 && OnRenew != nil {
				err := OnRenew()
				if err != nil {
					log.Printf("[ERROR] onrenew callback: %v\n", err)
				}
			}
		}
	}
}

// checkCertificateRenewal loops through all configured
// sites and looks for certificates to renew. Nothing is mutated
// through this function. The changes happen directly on disk.
// It returns the number of certificates renewed and any errors
// that occurred.
func processCertificateRenewal(configs []server.Config) (int, []error) {
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
