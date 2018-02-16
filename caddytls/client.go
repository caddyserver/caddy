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
	"github.com/xenolf/lego/acme"
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
		reg, err := client.Register()
		if err != nil {
			return nil, errors.New("registration error: " + err.Error())
		}
		leUser.Registration = reg

		if allowPrompts { // can't prompt a user who isn't there
			if !Agreed && reg.TosURL == "" {
				Agreed = promptUserAgreement(saURL, false) // TODO - latest URL
			}
			if !Agreed && reg.TosURL == "" {
				return nil, errors.New("user must agree to terms")
			}
		}

		err = client.AgreeToTOS()
		if err != nil {
			saveUser(storage, leUser) // Might as well try, right?
			return nil, errors.New("error agreeing to terms: " + err.Error())
		}

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

		// See which port TLS-SNI challenges will be accomplished on
		useTLSSNIPort := TLSSNIChallengePort
		if config.AltTLSSNIPort != "" {
			useTLSSNIPort = config.AltTLSSNIPort
		}

		// Always respect user's bind preferences by using config.ListenHost.
		// NOTE(Sep'16): At time of writing, SetHTTPAddress() and SetTLSAddress()
		// must be called before SetChallengeProvider(), since they reset the
		// challenge provider back to the default one!
		err := c.acmeClient.SetHTTPAddress(net.JoinHostPort(config.ListenHost, useHTTPPort))
		if err != nil {
			return nil, err
		}
		err = c.acmeClient.SetTLSAddress(net.JoinHostPort(config.ListenHost, useTLSSNIPort))
		if err != nil {
			return nil, err
		}

		// See if TLS challenge needs to be handled by our own facilities
		if caddy.HasListenerWithAddress(net.JoinHostPort(config.ListenHost, useTLSSNIPort)) {
			c.acmeClient.SetChallengeProvider(acme.TLSSNI01, tlsSNISolver{certCache: config.certCache})
		}

		// Disable any challenges that should not be used
		var disabledChallenges []acme.Challenge
		if DisableHTTPChallenge {
			disabledChallenges = append(disabledChallenges, acme.HTTP01)
		}
		if DisableTLSSNIChallenge {
			disabledChallenges = append(disabledChallenges, acme.TLSSNI01)
		}
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
		c.acmeClient.ExcludeChallenges([]acme.Challenge{acme.HTTP01, acme.TLSSNI01})
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

Attempts:
	for attempts := 0; attempts < 2; attempts++ {
		namesObtaining.Add([]string{name})
		acmeMu.Lock()
		certificate, failures := c.acmeClient.ObtainCertificate([]string{name}, true, nil, c.config.MustStaple)
		acmeMu.Unlock()
		namesObtaining.Remove([]string{name})
		if len(failures) > 0 {
			// Error - try to fix it or report it to the user and abort
			var errMsg string             // we'll combine all the failures into a single error message
			var promptedForAgreement bool // only prompt user for agreement at most once

			for errDomain, obtainErr := range failures {
				if obtainErr == nil {
					continue
				}
				if tosErr, ok := obtainErr.(acme.TOSError); ok {
					// Terms of Service agreement error; we can probably deal with this
					if !Agreed && !promptedForAgreement && c.AllowPrompts {
						Agreed = promptUserAgreement(tosErr.Detail, true) // TODO: Use latest URL
						promptedForAgreement = true
					}
					if Agreed || !c.AllowPrompts {
						err := c.acmeClient.AgreeToTOS()
						if err != nil {
							return errors.New("error agreeing to updated terms: " + err.Error())
						}
						continue Attempts
					}
				}

				// If user did not agree or it was any other kind of error, just append to the list of errors
				errMsg += "[" + errDomain + "] failed to get certificate: " + obtainErr.Error() + "\n"
			}
			return errors.New(errMsg)
		}

		// Success - immediately save the certificate resource
		err = saveCertResource(c.storage, certificate)
		if err != nil {
			return fmt.Errorf("error saving assets for %v: %v", name, err)
		}

		break
	}

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
			success = true
			break
		}

		// If the legal terms were updated and need to be
		// agreed to again, we can handle that.
		if _, ok := err.(acme.TOSError); ok {
			err := c.acmeClient.AgreeToTOS()
			if err != nil {
				return err
			}
			continue
		}

		// For any other kind of error, wait 10s and try again.
		wait := 10 * time.Second
		log.Printf("[ERROR] Renewing: %v; trying again in %s", err, wait)
		time.Sleep(wait)
	}

	if !success {
		return errors.New("too many renewal attempts; last error: " + err.Error())
	}

	caddy.EmitEvent(caddy.CertRenewEvent, name)

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
