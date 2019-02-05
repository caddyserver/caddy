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
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/xenolf/lego/certificate"
	"github.com/xenolf/lego/challenge"
	"github.com/xenolf/lego/challenge/http01"
	"github.com/xenolf/lego/challenge/tlsalpn01"
	"github.com/xenolf/lego/lego"
	"github.com/xenolf/lego/registration"
)

// acmeMu ensures that only one ACME challenge occurs at a time.
var acmeMu sync.Mutex

// acmeClient is a wrapper over acme.Client with
// some custom state attached. It is used to obtain,
// renew, and revoke certificates with ACME.
type acmeClient struct {
	config     *Config
	acmeClient *lego.Client
}

// listenerAddressInUse returns true if a TCP connection
// can be made to addr within a short time interval.
func listenerAddressInUse(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 250*time.Millisecond)
	if err == nil {
		conn.Close()
	}
	return err == nil
}

func (cfg *Config) newACMEClient(interactive bool) (*acmeClient, error) {
	// look up or create the user account
	leUser, err := cfg.getUser(cfg.Email)
	if err != nil {
		return nil, err
	}

	// ensure key type and timeout are set
	keyType := cfg.KeyType
	if keyType == "" {
		keyType = KeyType
	}
	certObtainTimeout := cfg.CertObtainTimeout
	if certObtainTimeout == 0 {
		certObtainTimeout = CertObtainTimeout
	}

	// ensure CA URL (directory endpoint) is set
	caURL := CA
	if cfg.CA != "" {
		caURL = cfg.CA
	}

	// ensure endpoint is secure (assume HTTPS if scheme is missing)
	if !strings.Contains(caURL, "://") {
		caURL = "https://" + caURL
	}
	u, err := url.Parse(caURL)
	if err != nil {
		return nil, err
	}

	if u.Scheme != "https" && !isLoopback(u.Host) && !isInternal(u.Host) {
		return nil, fmt.Errorf("%s: insecure CA URL (HTTPS required)", caURL)
	}

	clientKey := caURL + leUser.Email + string(keyType)

	// if an underlying client with this configuration already exists, reuse it
	cfg.acmeClientsMu.Lock()
	client, ok := cfg.acmeClients[clientKey]
	if !ok {
		// the client facilitates our communication with the CA server
		legoCfg := lego.NewConfig(&leUser)
		legoCfg.CADirURL = caURL
		legoCfg.UserAgent = buildUAString()
		legoCfg.HTTPClient.Timeout = HTTPTimeout
		legoCfg.Certificate = lego.CertificateConfig{
			KeyType: keyType,
			Timeout: certObtainTimeout,
		}
		client, err = lego.NewClient(legoCfg)
		if err != nil {
			cfg.acmeClientsMu.Unlock()
			return nil, err
		}
		cfg.acmeClients[clientKey] = client
	}
	cfg.acmeClientsMu.Unlock()

	// if not registered, the user must register an account
	// with the CA and agree to terms
	if leUser.Registration == nil {
		if interactive { // can't prompt a user who isn't there
			termsURL := client.GetToSURL()
			if !cfg.Agreed && termsURL != "" {
				cfg.Agreed = cfg.askUserAgreement(client.GetToSURL())
			}
			if !cfg.Agreed && termsURL != "" {
				return nil, fmt.Errorf("user must agree to CA terms")
			}
		}

		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: cfg.Agreed})
		if err != nil {
			return nil, fmt.Errorf("registration error: %v", err)
		}
		leUser.Registration = reg

		// persist the user to storage
		err = cfg.saveUser(leUser)
		if err != nil {
			return nil, fmt.Errorf("could not save user: %v", err)
		}
	}

	c := &acmeClient{
		config:     cfg,
		acmeClient: client,
	}

	if cfg.DNSProvider == nil {
		// Use HTTP and TLS-ALPN challenges by default

		// figure out which ports we'll be serving the challenges on
		useHTTPPort := HTTPChallengePort
		useTLSALPNPort := TLSALPNChallengePort
		if HTTPPort > 0 && HTTPPort != HTTPChallengePort {
			useHTTPPort = HTTPPort
		}
		if HTTPSPort > 0 && HTTPSPort != TLSALPNChallengePort {
			useTLSALPNPort = HTTPSPort
		}
		if cfg.AltHTTPPort > 0 {
			useHTTPPort = cfg.AltHTTPPort
		}
		if cfg.AltTLSALPNPort > 0 {
			useTLSALPNPort = cfg.AltTLSALPNPort
		}

		// If this machine is already listening on the HTTP or TLS-ALPN port
		// designated for the challenges, then we need to handle the challenges
		// a little differently: for HTTP, we will answer the challenge request
		// using our own HTTP handler (the HandleHTTPChallenge function - this
		// works only because challenge info is written to storage associated
		// with cfg when the challenge is initiated); for TLS-ALPN, we will add
		// the challenge cert to our cert cache and serve it up during the
		// handshake. As for the default solvers...  we are careful to honor the
		// listener bind preferences by using cfg.ListenHost.
		var httpSolver, alpnSolver challenge.Provider
		httpSolver = http01.NewProviderServer(cfg.ListenHost, fmt.Sprintf("%d", useHTTPPort))
		alpnSolver = tlsalpn01.NewProviderServer(cfg.ListenHost, fmt.Sprintf("%d", useTLSALPNPort))
		if listenerAddressInUse(net.JoinHostPort(cfg.ListenHost, fmt.Sprintf("%d", useHTTPPort))) {
			httpSolver = nil
		}
		if listenerAddressInUse(net.JoinHostPort(cfg.ListenHost, fmt.Sprintf("%d", useTLSALPNPort))) {
			alpnSolver = tlsALPNSolver{certCache: cfg.certCache}
		}

		// because of our nifty Storage interface, we can distribute the HTTP and
		// TLS-ALPN challenges across all instances that share the same storage -
		// in fact, this is required now for successful solving of the HTTP challenge
		// if the port is already in use, since we must write the challenge info
		// to storage for the HTTPChallengeHandler to solve it successfully
		c.acmeClient.Challenge.SetHTTP01Provider(distributedSolver{
			config:         cfg,
			providerServer: httpSolver,
		})
		c.acmeClient.Challenge.SetTLSALPN01Provider(distributedSolver{
			config:         cfg,
			providerServer: alpnSolver,
		})

		// disable any challenges that should not be used
		if cfg.DisableHTTPChallenge {
			c.acmeClient.Challenge.Remove(challenge.HTTP01)
		}
		if cfg.DisableTLSALPNChallenge {
			c.acmeClient.Challenge.Remove(challenge.TLSALPN01)
		}
	} else {
		// Otherwise, use DNS challenge exclusively
		c.acmeClient.Challenge.Remove(challenge.HTTP01)
		c.acmeClient.Challenge.Remove(challenge.TLSALPN01)
		c.acmeClient.Challenge.SetDNS01Provider(cfg.DNSProvider)
	}

	return c, nil
}

// lockKey returns a key for a lock that is specific to the operation
// named op being performed related to domainName and this config's CA.
func (cfg *Config) lockKey(op, domainName string) string {
	return fmt.Sprintf("%s_%s_%s", op, domainName, cfg.CA)
}

// Obtain obtains a single certificate for name. It stores the certificate
// on the disk if successful. This function is safe for concurrent use.
//
// Our storage mechanism only supports one name per certificate, so this
// function (along with Renew and Revoke) only accepts one domain as input.
// It could be easily modified to support SAN certificates if our storage
// mechanism is upgraded later, but that will increase logical complexity
// in other areas.
//
// Callers who have access to a Config value should use the ObtainCert
// method on that instead of this lower-level method.
func (c *acmeClient) Obtain(name string) error {
	// ensure idempotency of the obtain operation for this name
	lockKey := c.config.lockKey("cert_acme", name)
	err := c.config.certCache.storage.Lock(lockKey)
	if err != nil {
		return err
	}
	defer func() {
		if err := c.config.certCache.storage.Unlock(lockKey); err != nil {
			log.Printf("[ERROR][%s] Obtain: Unable to unlock '%s': %v", name, lockKey, err)
		}
	}()

	// check if obtain is still needed -- might have
	// been obtained during lock
	if c.config.storageHasCertResources(name) {
		log.Printf("[INFO][%s] Obtain: Certificate already exists in storage", name)
		return nil
	}

	for attempts := 0; attempts < 2; attempts++ {
		request := certificate.ObtainRequest{
			Domains:    []string{name},
			Bundle:     true,
			MustStaple: c.config.MustStaple,
		}
		acmeMu.Lock()
		certificate, err := c.acmeClient.Certificate.Obtain(request)
		acmeMu.Unlock()
		if err != nil {
			return fmt.Errorf("[%s] failed to obtain certificate: %s", name, err)
		}

		// double-check that we actually got a certificate, in case there's a bug upstream (see issue mholt/caddy#2121)
		if certificate.Domain == "" || certificate.Certificate == nil {
			return fmt.Errorf("returned certificate was empty; probably an unchecked error obtaining it")
		}

		// Success - immediately save the certificate resource
		err = c.config.saveCertResource(certificate)
		if err != nil {
			return fmt.Errorf("error saving assets for %v: %v", name, err)
		}

		break
	}

	if c.config.OnEvent != nil {
		c.config.OnEvent("acme_cert_obtained", name)
	}

	return nil
}

// Renew renews the managed certificate for name. It puts the renewed
// certificate into storage (not the cache). This function is safe for
// concurrent use.
//
// Callers who have access to a Config value should use the RenewCert
// method on that instead of this lower-level method.
func (c *acmeClient) Renew(name string) error {
	// ensure idempotency of the renew operation for this name
	lockKey := c.config.lockKey("cert_acme", name)
	err := c.config.certCache.storage.Lock(lockKey)
	if err != nil {
		return err
	}
	defer func() {
		if err := c.config.certCache.storage.Unlock(lockKey); err != nil {
			log.Printf("[ERROR][%s] Renew: Unable to unlock '%s': %v", name, lockKey, err)
		}
	}()

	// Prepare for renewal (load PEM cert, key, and meta)
	certRes, err := c.config.loadCertResource(name)
	if err != nil {
		return err
	}

	// Check if renew is still needed - might have been renewed while waiting for lock
	if !c.config.managedCertNeedsRenewal(certRes) {
		log.Printf("[INFO][%s] Renew: Certificate appears to have been renewed already", name)
		return nil
	}

	// Perform renewal and retry if necessary, but not too many times.
	var newCertMeta *certificate.Resource
	var success bool
	for attempts := 0; attempts < 2; attempts++ {
		acmeMu.Lock()
		newCertMeta, err = c.acmeClient.Certificate.Renew(certRes, true, c.config.MustStaple)
		acmeMu.Unlock()
		if err == nil {
			// double-check that we actually got a certificate; check a couple fields, just in case
			if newCertMeta == nil || newCertMeta.Domain == "" || newCertMeta.Certificate == nil {
				err = fmt.Errorf("returned certificate was empty; probably an unchecked error renewing it")
			} else {
				success = true
				break
			}
		}

		// wait a little bit and try again
		wait := 10 * time.Second
		log.Printf("[ERROR] Renewing [%v]: %v; trying again in %s", name, err, wait)
		time.Sleep(wait)
	}

	if !success {
		return fmt.Errorf("too many renewal attempts; last error: %v", err)
	}

	if c.config.OnEvent != nil {
		c.config.OnEvent("acme_cert_renewed", name)
	}

	return c.config.saveCertResource(newCertMeta)
}

// Revoke revokes the certificate for name and deletes
// it from storage.
func (c *acmeClient) Revoke(name string) error {
	if !c.config.certCache.storage.Exists(StorageKeys.SitePrivateKey(c.config.CA, name)) {
		return fmt.Errorf("private key not found for %s", name)
	}

	certRes, err := c.config.loadCertResource(name)
	if err != nil {
		return err
	}

	err = c.acmeClient.Certificate.Revoke(certRes.Certificate)
	if err != nil {
		return err
	}

	if c.config.OnEvent != nil {
		c.config.OnEvent("acme_cert_revoked", name)
	}

	err = c.config.certCache.storage.Delete(StorageKeys.SiteCert(c.config.CA, name))
	if err != nil {
		return fmt.Errorf("certificate revoked, but unable to delete certificate file: %v", err)
	}
	err = c.config.certCache.storage.Delete(StorageKeys.SitePrivateKey(c.config.CA, name))
	if err != nil {
		return fmt.Errorf("certificate revoked, but unable to delete private key: %v", err)
	}
	err = c.config.certCache.storage.Delete(StorageKeys.SiteMeta(c.config.CA, name))
	if err != nil {
		return fmt.Errorf("certificate revoked, but unable to delete certificate metadata: %v", err)
	}

	return nil
}

func buildUAString() string {
	ua := "CertMagic"
	if UserAgent != "" {
		ua += " " + UserAgent
	}
	return ua
}

// Some default values passed down to the underlying lego client.
var (
	UserAgent   string
	HTTPTimeout = 30 * time.Second
)
