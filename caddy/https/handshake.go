package https

import (
	"bytes"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/mholt/caddy/server"
	"github.com/xenolf/lego/acme"
)

// GetCertificate gets a certificate to satisfy clientHello as long as
// the certificate is already cached in memory.
//
// This function is safe for use as a tls.Config.GetCertificate callback.
func GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert, err := getCertDuringHandshake(clientHello.ServerName, false)
	return cert.Certificate, err
}

// GetOrObtainCertificate will get a certificate to satisfy clientHello, even
// if that means obtaining a new certificate from a CA during the handshake.
// It first checks the in-memory cache, then accesses disk, then accesses the
// network if it must. An obtained certificate will be stored on disk and
// cached in memory.
//
// This function is safe for use as a tls.Config.GetCertificate callback.
func GetOrObtainCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert, err := getCertDuringHandshake(clientHello.ServerName, true)
	return cert.Certificate, err
}

// getCertDuringHandshake will get a certificate for name. It first tries
// the in-memory cache, then, if obtainIfNecessary is true, it goes to disk,
// then asks the CA for a certificate if necessary.
//
// This function is safe for concurrent use.
func getCertDuringHandshake(name string, obtainIfNecessary bool) (Certificate, error) {
	// First check our in-memory cache to see if we've already loaded it
	cert, ok := getCertificate(name)
	if ok {
		return cert, nil
	}

	if obtainIfNecessary {
		// TODO: Mitigate abuse!
		var err error

		// Then check to see if we have one on disk
		cert, err := cacheManagedCertificate(name, true)
		if err != nil {
			return cert, err
		} else if cert.Certificate != nil {
			cert, err := handshakeMaintenance(name, cert)
			if err != nil {
				log.Printf("[ERROR] Maintaining newly-loaded certificate for %s: %v", name, err)
			}
			return cert, err
		}

		// Only option left is to get one from LE, but the name has to qualify first
		if !HostQualifies(name) {
			return cert, errors.New("hostname '" + name + "' does not qualify for certificate")
		}

		// By this point, we need to obtain one from the CA.
		return obtainOnDemandCertificate(name)
	}

	return Certificate{}, nil
}

// obtainOnDemandCertificate obtains a certificate for name for the given
// clientHello. If another goroutine has already started obtaining a cert
// for name, it will wait and use what the other goroutine obtained.
//
// This function is safe for use by multiple concurrent goroutines.
func obtainOnDemandCertificate(name string) (Certificate, error) {
	// We must protect this process from happening concurrently, so synchronize.
	obtainCertWaitChansMu.Lock()
	wait, ok := obtainCertWaitChans[name]
	if ok {
		// lucky us -- another goroutine is already obtaining the certificate.
		// wait for it to finish obtaining the cert and then we'll use it.
		obtainCertWaitChansMu.Unlock()
		<-wait
		return getCertDuringHandshake(name, false) // passing in true might result in infinite loop if obtain failed
	}

	// looks like it's up to us to do all the work and obtain the cert
	wait = make(chan struct{})
	obtainCertWaitChans[name] = wait
	obtainCertWaitChansMu.Unlock()

	// Unblock waiters and delete waitgroup when we return
	defer func() {
		obtainCertWaitChansMu.Lock()
		close(wait)
		delete(obtainCertWaitChans, name)
		obtainCertWaitChansMu.Unlock()
	}()

	log.Printf("[INFO] Obtaining new certificate for %s", name)

	// obtain cert
	client, err := NewACMEClientGetEmail(server.Config{}, false)
	if err != nil {
		return Certificate{}, errors.New("error creating client: " + err.Error())
	}
	client.Configure("") // TODO: which BindHost?
	err = client.Obtain([]string{name})
	if err != nil {
		return Certificate{}, err
	}

	// The certificate is on disk; now just start over to load it and serve it
	return getCertDuringHandshake(name, false) // pass in false as a fail-safe from infinite-looping
}

// handshakeMaintenance performs a check on cert for expiration and OCSP
// validity.
//
// This function is safe for use by multiple concurrent goroutines.
func handshakeMaintenance(name string, cert Certificate) (Certificate, error) {
	// fmt.Println("ON-DEMAND CERT?", cert.OnDemand)
	// if !cert.OnDemand {
	// 	return cert, nil
	// }
	fmt.Println("Checking expiration of cert; on-demand:", cert.OnDemand)

	// Check cert expiration
	timeLeft := cert.NotAfter.Sub(time.Now().UTC())
	if timeLeft < renewDurationBefore {
		log.Printf("[INFO] Certificate for %v expires in %v; attempting renewal", cert.Names, timeLeft)
		return renewDynamicCertificate(name)
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

// renewDynamicCertificate renews currentCert using the clientHello. It returns the
// certificate to use and an error, if any. currentCert may be returned even if an
// error occurs, since we perform renewals before they expire and it may still be
// usable. name should already be lower-cased before calling this function.
//
// This function is safe for use by multiple concurrent goroutines.
func renewDynamicCertificate(name string) (Certificate, error) {
	obtainCertWaitChansMu.Lock()
	wait, ok := obtainCertWaitChans[name]
	if ok {
		// lucky us -- another goroutine is already renewing the certificate.
		// wait for it to finish, then we'll use the new one.
		obtainCertWaitChansMu.Unlock()
		<-wait
		return getCertDuringHandshake(name, false)
	}

	// looks like it's up to us to do all the work and renew the cert
	wait = make(chan struct{})
	obtainCertWaitChans[name] = wait
	obtainCertWaitChansMu.Unlock()

	// unblock waiters and delete waitgroup when we return
	defer func() {
		obtainCertWaitChansMu.Lock()
		close(wait)
		delete(obtainCertWaitChans, name)
		obtainCertWaitChansMu.Unlock()
	}()

	log.Printf("[INFO] Renewing certificate for %s", name)

	client, err := NewACMEClient("", false) // renewals don't use email
	if err != nil {
		return Certificate{}, err
	}
	client.Configure("") // TODO: Bind address of relevant listener, yuck
	err = client.Renew(name)
	if err != nil {
		return Certificate{}, err
	}

	return getCertDuringHandshake(name, false)
}

// stapleOCSP staples OCSP information to cert for hostname name.
// If you have it handy, you should pass in the PEM-encoded certificate
// bundle; otherwise the DER-encoded cert will have to be PEM-encoded.
// If you don't have the PEM blocks handy, just pass in nil.
//
// Errors here are not necessarily fatal, it could just be that the
// certificate doesn't have an issuer URL.
func stapleOCSP(cert *Certificate, pemBundle []byte) error {
	if pemBundle == nil {
		// The function in the acme package that gets OCSP requires a PEM-encoded cert
		bundle := new(bytes.Buffer)
		for _, derBytes := range cert.Certificate.Certificate {
			pem.Encode(bundle, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
		}
		pemBundle = bundle.Bytes()
	}

	ocspBytes, ocspResp, err := acme.GetOCSPForCert(pemBundle)
	if err != nil {
		return err
	}

	cert.Certificate.OCSPStaple = ocspBytes
	cert.OCSP = ocspResp

	return nil
}

// obtainCertWaitChans is used to coordinate obtaining certs for each hostname.
var obtainCertWaitChans = make(map[string]chan struct{})
var obtainCertWaitChansMu sync.Mutex
