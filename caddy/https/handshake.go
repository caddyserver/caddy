package https

import (
	"bytes"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mholt/caddy/server"
	"github.com/xenolf/lego/acme"
)

// GetCertificate gets a certificate to satisfy clientHello as long as
// the certificate is already cached in memory. It will not be loaded
// from disk or obtained from the CA during the handshake.
//
// This function is safe for use as a tls.Config.GetCertificate callback.
func GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert, err := getCertDuringHandshake(clientHello.ServerName, false, false)
	return &cert.Certificate, err
}

// GetOrObtainCertificate will get a certificate to satisfy clientHello, even
// if that means obtaining a new certificate from a CA during the handshake.
// It first checks the in-memory cache, then accesses disk, then accesses the
// network if it must. An obtained certificate will be stored on disk and
// cached in memory.
//
// This function is safe for use as a tls.Config.GetCertificate callback.
func GetOrObtainCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert, err := getCertDuringHandshake(clientHello.ServerName, true, true)
	return &cert.Certificate, err
}

// getCertDuringHandshake will get a certificate for name. It first tries
// the in-memory cache. If no certificate for name is in the cache and if
// loadIfNecessary == true, it goes to disk to load it into the cache and
// serve it. If it's not on disk and if obtainIfNecessary == true, the
// certificate will be obtained from the CA, cached, and served. If
// obtainIfNecessary is true, then loadIfNecessary must also be set to true.
// An error will be returned if and only if no certificate is available.
//
// This function is safe for concurrent use.
func getCertDuringHandshake(name string, loadIfNecessary, obtainIfNecessary bool) (Certificate, error) {
	// First check our in-memory cache to see if we've already loaded it
	cert, matched, defaulted := getCertificate(name)
	if matched {
		return cert, nil
	}

	if loadIfNecessary {
		// Then check to see if we have one on disk
		loadedCert, err := cacheManagedCertificate(name, true)
		if err == nil {
			loadedCert, err = handshakeMaintenance(name, loadedCert)
			if err != nil {
				log.Printf("[ERROR] Maintaining newly-loaded certificate for %s: %v", name, err)
			}
			return loadedCert, nil
		}

		if obtainIfNecessary {
			// By this point, we need to ask the CA for a certificate

			name = strings.ToLower(name)

			// Make sure aren't over any applicable limits
			err := checkLimitsForObtainingNewCerts(name)
			if err != nil {
				return Certificate{}, err
			}

			// Name has to qualify for a certificate
			if !HostQualifies(name) {
				return cert, errors.New("hostname '" + name + "' does not qualify for certificate")
			}

			// Obtain certificate from the CA
			return obtainOnDemandCertificate(name)
		}
	}

	if defaulted {
		return cert, nil
	}

	return Certificate{}, errors.New("no certificate for " + name)
}

// checkLimitsForObtainingNewCerts checks to see if name can be issued right
// now according to mitigating factors we keep track of and preferences the
// user has set. If a non-nil error is returned, do not issue a new certificate
// for name.
func checkLimitsForObtainingNewCerts(name string) error {
	// User can set hard limit for number of certs for the process to issue
	if onDemandMaxIssue > 0 && atomic.LoadInt32(OnDemandIssuedCount) >= onDemandMaxIssue {
		return fmt.Errorf("%s: maximum certificates issued (%d)", name, onDemandMaxIssue)
	}

	// Make sure name hasn't failed a challenge recently
	failedIssuanceMu.RLock()
	when, ok := failedIssuance[name]
	failedIssuanceMu.RUnlock()
	if ok {
		return fmt.Errorf("%s: throttled; refusing to issue cert since last attempt on %s failed", name, when.String())
	}

	// Make sure, if we've issued a few certificates already, that we haven't
	// issued any recently
	lastIssueTimeMu.Lock()
	since := time.Since(lastIssueTime)
	lastIssueTimeMu.Unlock()
	if atomic.LoadInt32(OnDemandIssuedCount) >= 10 && since < 10*time.Minute {
		return fmt.Errorf("%s: throttled; last certificate was obtained %v ago", name, since)
	}

	// 👍Good to go
	return nil
}

// obtainOnDemandCertificate obtains a certificate for name for the given
// name. If another goroutine has already started obtaining a cert for
// name, it will wait and use what the other goroutine obtained.
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
		return getCertDuringHandshake(name, true, false)
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
		// Failed to solve challenge, so don't allow another on-demand
		// issue for this name to be attempted for a little while.
		failedIssuanceMu.Lock()
		failedIssuance[name] = time.Now()
		go func(name string) {
			time.Sleep(5 * time.Minute)
			failedIssuanceMu.Lock()
			delete(failedIssuance, name)
			failedIssuanceMu.Unlock()
		}(name)
		failedIssuanceMu.Unlock()
		return Certificate{}, err
	}

	// Success - update counters and stuff
	atomic.AddInt32(OnDemandIssuedCount, 1)
	lastIssueTimeMu.Lock()
	lastIssueTime = time.Now()
	lastIssueTimeMu.Unlock()

	// The certificate is already on disk; now just start over to load it and serve it
	return getCertDuringHandshake(name, true, false)
}

// handshakeMaintenance performs a check on cert for expiration and OCSP
// validity.
//
// This function is safe for use by multiple concurrent goroutines.
func handshakeMaintenance(name string, cert Certificate) (Certificate, error) {
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
		return getCertDuringHandshake(name, true, false)
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

	client, err := NewACMEClientGetEmail(server.Config{}, false)
	if err != nil {
		return Certificate{}, err
	}
	client.Configure("") // TODO: Bind address of relevant listener, yuck
	err = client.Renew(name)
	if err != nil {
		return Certificate{}, err
	}

	return getCertDuringHandshake(name, true, false)
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

// OnDemandIssuedCount is the number of certificates that have been issued
// on-demand by this process. It is only safe to modify this count atomically.
// If it reaches onDemandMaxIssue, on-demand issuances will fail.
var OnDemandIssuedCount = new(int32)

// onDemandMaxIssue is set based on max_certs in tls config. It specifies the
// maximum number of certificates that can be issued.
// TODO: This applies globally, but we should probably make a server-specific
// way to keep track of these limits and counts, since it's specified in the
// Caddyfile...
var onDemandMaxIssue int32

// failedIssuance is a set of names that we recently failed to get a
// certificate for from the ACME CA. They are removed after some time.
// When a name is in this map, do not issue a certificate for it on-demand.
var failedIssuance = make(map[string]time.Time)
var failedIssuanceMu sync.RWMutex

// lastIssueTime records when we last obtained a certificate successfully.
// If this value is recent, do not make any on-demand certificate requests.
var lastIssueTime time.Time
var lastIssueTimeMu sync.Mutex
