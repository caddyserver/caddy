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
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/telemetry"
	"github.com/xenolf/lego/acmev2"
)

// acmeMu ensures that only one ACME challenge occurs at a time.
var acmeMu sync.Mutex

// ACMEClient is a wrapper over acme.Client with
// some custom state attached. It is used to obtain,
// renew, and revoke certificates with ACME.
type ACMEClient struct {
	AllowPrompts bool
	config       *Config
	acmeClient   *acme.Client
	storage      Storage
}

// newACMEClient creates a new ACMEClient given an email and whether
// prompting the user is allowed. It's a variable so we can mock in tests.
var newACMEClient = func(config *Config, allowPrompts bool) (*ACMEClient, error) {
	storage, err := config.StorageFor(config.CAUrl)
	if err != nil {
		return nil, err
	}

	// Look up or create the LE user account
	leUser, err := getUser(storage, config.ACMEEmail)
	if err != nil {
		return nil, err
	}

	// ensure key type is set
	keyType := DefaultKeyType
	if config.KeyType != "" {
		keyType = config.KeyType
	}

	// ensure CA URL (directory endpoint) is set
	caURL := DefaultCAUrl
	if config.CAUrl != "" {
		caURL = config.CAUrl
	}

	// ensure endpoint is secure (assume HTTPS if scheme is missing)
	if !strings.Contains(caURL, "://") {
		caURL = "https://" + caURL
	}
	u, err := url.Parse(caURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" && !caddy.IsLoopback(u.Host) && !caddy.IsInternal(u.Host) {
		return nil, fmt.Errorf("%s: insecure CA URL (HTTPS required)", caURL)
	}

	// The client facilitates our communication with the CA server.
	client, err := acme.NewClient(caURL, &leUser, keyType)
	if err != nil {
		return nil, err
	}

	// If not registered, the user must register an account with the CA
	// and agree to terms
	if leUser.Registration == nil {
		if allowPrompts { // can't prompt a user who isn't there
			termsURL := client.GetToSURL()
			if !Agreed && termsURL != "" {
				Agreed = askUserAgreement(client.GetToSURL())
			}
			if !Agreed && termsURL != "" {
				return nil, errors.New("user must agree to CA terms (use -agree flag)")
			}
		}

		reg, err := client.Register(Agreed)
		if err != nil {
			return nil, errors.New("registration error: " + err.Error())
		}
		leUser.Registration = reg

		// save user to the file system
		err = saveUser(storage, leUser)
		if err != nil {
			return nil, errors.New("could not save user: " + err.Error())
		}
	}

	c := &ACMEClient{
		AllowPrompts: allowPrompts,
		config:       config,
		acmeClient:   client,
		storage:      storage,
	}

	if config.DNSProvider == "" {
		// Use HTTP and TLS-SNI challenges by default

		// See if HTTP challenge needs to be proxied
		useHTTPPort := HTTPChallengePort
		if config.AltHTTPPort != "" {
			useHTTPPort = config.AltHTTPPort
		}
		if caddy.HasListenerWithAddress(net.JoinHostPort(config.ListenHost, useHTTPPort)) {
			useHTTPPort = DefaultHTTPAlternatePort
		}

		// TODO: tls-sni challenge was removed in January 2018, but a variant of it might return
		// See which port TLS-SNI challenges will be accomplished on
		// useTLSSNIPort := TLSSNIChallengePort
		// if config.AltTLSSNIPort != "" {
		// 	useTLSSNIPort = config.AltTLSSNIPort
		// }
		// err := c.acmeClient.SetTLSAddress(net.JoinHostPort(config.ListenHost, useTLSSNIPort))
		// if err != nil {
		// 	return nil, err
		// }

		// if using file storage, we can distribute the HTTP challenge across
		// all instances sharing the acme folder; either way, we must still set
		// the address for the default HTTP provider server
		var useDistributedHTTPSolver bool
		if storage, err := c.config.StorageFor(c.config.CAUrl); err == nil {
			if _, ok := storage.(*FileStorage); ok {
				useDistributedHTTPSolver = true
			}
		}
		if useDistributedHTTPSolver {
			c.acmeClient.SetChallengeProvider(acme.HTTP01, distributedHTTPSolver{
				// being careful to respect user's listener bind preferences
				httpProviderServer: acme.NewHTTPProviderServer(config.ListenHost, useHTTPPort),
			})
		} else {
			// Always respect user's bind preferences by using config.ListenHost.
			// NOTE(Sep'16): At time of writing, SetHTTPAddress() and SetTLSAddress()
			// must be called before SetChallengeProvider() (see above), since they reset
			// the challenge provider back to the default one! (still true in March 2018)
			err := c.acmeClient.SetHTTPAddress(net.JoinHostPort(config.ListenHost, useHTTPPort))
			if err != nil {
				return nil, err
			}
		}

		// TODO: tls-sni challenge was removed in January 2018, but a variant of it might return
		// See if TLS challenge needs to be handled by our own facilities
		// if caddy.HasListenerWithAddress(net.JoinHostPort(config.ListenHost, useTLSSNIPort)) {
		// 	c.acmeClient.SetChallengeProvider(acme.TLSSNI01, tlsSNISolver{certCache: config.certCache})
		// }

		// Disable any challenges that should not be used
		var disabledChallenges []acme.Challenge
		if DisableHTTPChallenge {
			disabledChallenges = append(disabledChallenges, acme.HTTP01)
		}
		// TODO: tls-sni challenge was removed in January 2018, but a variant of it might return
		// if DisableTLSSNIChallenge {
		// 	disabledChallenges = append(disabledChallenges, acme.TLSSNI01)
		// }
		if len(disabledChallenges) > 0 {
			c.acmeClient.ExcludeChallenges(disabledChallenges)
		}
	} else {
		// Otherwise, use DNS challenge exclusively

		// Load provider constructor function
		provFn, ok := dnsProviders[config.DNSProvider]
		if !ok {
			return nil, errors.New("unknown DNS provider by name '" + config.DNSProvider + "'")
		}

		// We could pass credentials to create the provider, but for now
		// just let the solver package get them from the environment
		prov, err := provFn()
		if err != nil {
			return nil, err
		}

		// Use the DNS challenge exclusively
		// TODO: tls-sni challenge was removed in January 2018, but a variant of it might return
		// c.acmeClient.ExcludeChallenges([]acme.Challenge{acme.HTTP01, acme.TLSSNI01})
		c.acmeClient.ExcludeChallenges([]acme.Challenge{acme.HTTP01})
		c.acmeClient.SetChallengeProvider(acme.DNS01, prov)
	}

	return c, nil
}

// Obtain obtains a single certificate for name. It stores the certificate
// on the disk if successful. This function is safe for concurrent use.
//
// Right now our storage mechanism only supports one name per certificate,
// so this function (along with Renew and Revoke) only accepts one domain
// as input. It can be easily modified to support SAN certificates if our
// storage mechanism is upgraded later.
//
// Callers who have access to a Config value should use the ObtainCert
// method on that instead of this lower-level method.
func (c *ACMEClient) Obtain(name string) error {
	waiter, err := c.storage.TryLock(name)
	if err != nil {
		return err
	}
	if waiter != nil {
		log.Printf("[INFO] Certificate for %s is already being obtained elsewhere and stored; waiting", name)
		waiter.Wait()
		return nil // we assume the process with the lock succeeded, rather than hammering this execution path again
	}
	defer func() {
		if err := c.storage.Unlock(name); err != nil {
			log.Printf("[ERROR] Unable to unlock obtain call for %s: %v", name, err)
		}
	}()

	for attempts := 0; attempts < 2; attempts++ {
		namesObtaining.Add([]string{name})
		acmeMu.Lock()
		certificate, err := c.acmeClient.ObtainCertificate([]string{name}, true, nil, c.config.MustStaple)
		acmeMu.Unlock()
		namesObtaining.Remove([]string{name})
		if err != nil {
			// for a certain kind of error, we can enumerate the error per-domain
			if failures, ok := err.(acme.ObtainError); ok && len(failures) > 0 {
				var errMsg string // combine all the failures into a single error message
				for errDomain, obtainErr := range failures {
					if obtainErr == nil {
						continue
					}
					errMsg += fmt.Sprintf("[%s] failed to get certificate: %v\n", errDomain, obtainErr)
				}
				return errors.New(errMsg)
			}

			return fmt.Errorf("[%s] failed to obtain certificate: %v", name, err)
		}

		// double-check that we actually got a certificate, in case there's a bug upstream (see issue #2121)
		if certificate.Domain == "" || certificate.Certificate == nil {
			return errors.New("returned certificate was empty; probably an unchecked error obtaining it")
		}

		// Success - immediately save the certificate resource
		err = saveCertResource(c.storage, certificate)
		if err != nil {
			return fmt.Errorf("error saving assets for %v: %v", name, err)
		}

		break
	}

	go telemetry.Increment("tls_acme_certs_obtained")

	return nil
}

// Renew renews the managed certificate for name. It puts the renewed
// certificate into storage (not the cache). This function is safe for
// concurrent use.
//
// Callers who have access to a Config value should use the RenewCert
// method on that instead of this lower-level method.
func (c *ACMEClient) Renew(name string) error {
	waiter, err := c.storage.TryLock(name)
	if err != nil {
		return err
	}
	if waiter != nil {
		log.Printf("[INFO] Certificate for %s is already being renewed elsewhere and stored; waiting", name)
		waiter.Wait()
		return nil // assume that the worker that renewed the cert succeeded; avoid hammering this path over and over
	}
	defer func() {
		if err := c.storage.Unlock(name); err != nil {
			log.Printf("[ERROR] Unable to unlock renew call for %s: %v", name, err)
		}
	}()

	// Prepare for renewal (load PEM cert, key, and meta)
	siteData, err := c.storage.LoadSite(name)
	if err != nil {
		return err
	}
	var certMeta acme.CertificateResource
	err = json.Unmarshal(siteData.Meta, &certMeta)
	certMeta.Certificate = siteData.Cert
	certMeta.PrivateKey = siteData.Key

	// Perform renewal and retry if necessary, but not too many times.
	var newCertMeta acme.CertificateResource
	var success bool
	for attempts := 0; attempts < 2; attempts++ {
		namesObtaining.Add([]string{name})
		acmeMu.Lock()
		newCertMeta, err = c.acmeClient.RenewCertificate(certMeta, true, c.config.MustStaple)
		acmeMu.Unlock()
		namesObtaining.Remove([]string{name})
		if err == nil {
			// double-check that we actually got a certificate; check a couple fields
			// TODO: This is a temporary workaround for what I think is a bug in the acmev2 package (March 2018)
			// but it might not hurt to keep this extra check in place
			if newCertMeta.Domain == "" || newCertMeta.Certificate == nil {
				err = errors.New("returned certificate was empty; probably an unchecked error renewing it")
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
		return errors.New("too many renewal attempts; last error: " + err.Error())
	}

	caddy.EmitEvent(caddy.CertRenewEvent, name)
	go telemetry.Increment("tls_acme_certs_renewed")

	return saveCertResource(c.storage, newCertMeta)
}

// Revoke revokes the certificate for name and deletes
// it from storage.
func (c *ACMEClient) Revoke(name string) error {
	siteExists, err := c.storage.SiteExists(name)
	if err != nil {
		return err
	}

	if !siteExists {
		return errors.New("no certificate and key for " + name)
	}

	siteData, err := c.storage.LoadSite(name)
	if err != nil {
		return err
	}

	err = c.acmeClient.RevokeCertificate(siteData.Cert)
	if err != nil {
		return err
	}

	go telemetry.Increment("tls_acme_certs_revoked")

	err = c.storage.DeleteSite(name)
	if err != nil {
		return errors.New("certificate revoked, but unable to delete certificate file: " + err.Error())
	}

	return nil
}

// namesObtaining is a set of hostnames with thread-safe
// methods. A name should be in this set only while this
// package is in the process of obtaining a certificate
// for the name. ACME challenges that are received for
// names which are not in this set were not initiated by
// this package and probably should not be handled by
// this package.
var namesObtaining = nameCoordinator{names: make(map[string]struct{})}

type nameCoordinator struct {
	names map[string]struct{}
	mu    sync.RWMutex
}

// Add adds names to c. It is safe for concurrent use.
func (c *nameCoordinator) Add(names []string) {
	c.mu.Lock()
	for _, name := range names {
		c.names[strings.ToLower(name)] = struct{}{}
	}
	c.mu.Unlock()
}

// Remove removes names from c. It is safe for concurrent use.
func (c *nameCoordinator) Remove(names []string) {
	c.mu.Lock()
	for _, name := range names {
		delete(c.names, strings.ToLower(name))
	}
	c.mu.Unlock()
}

// Has returns true if c has name. It is safe for concurrent use.
func (c *nameCoordinator) Has(name string) bool {
	hostname, _, err := net.SplitHostPort(name)
	if err != nil {
		hostname = name
	}
	c.mu.RLock()
	_, ok := c.names[strings.ToLower(hostname)]
	c.mu.RUnlock()
	return ok
}

// KnownACMECAs is a list of ACME directory endpoints of
// known, public, and trusted ACME-compatible certificate
// authorities.
var KnownACMECAs = []string{
	"https://acme-v02.api.letsencrypt.org/directory",
}
