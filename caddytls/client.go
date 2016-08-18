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

// ACMEClient is an acme.Client with custom state attached.
type ACMEClient struct {
	*acme.Client
	AllowPrompts bool
	config       *Config
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
	if u.Scheme != "https" && !caddy.IsLoopback(u.Host) && !strings.HasPrefix(u.Host, "10.") {
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

	c := &ACMEClient{Client: client, AllowPrompts: allowPrompts, config: config}

	if config.DNSProvider == "" {
		// Use HTTP and TLS-SNI challenges by default

		// See if HTTP challenge needs to be proxied
		useHTTPPort := "" // empty port value will use challenge default
		if caddy.HasListenerWithAddress(net.JoinHostPort(config.ListenHost, HTTPChallengePort)) {
			useHTTPPort = config.AltHTTPPort
			if useHTTPPort == "" {
				useHTTPPort = DefaultHTTPAlternatePort
			}
		}

		// See if TLS challenge needs to be handled by our own facilities
		if caddy.HasListenerWithAddress(net.JoinHostPort(config.ListenHost, TLSSNIChallengePort)) {
			c.SetChallengeProvider(acme.TLSSNI01, tlsSniSolver{})
		}

		// Always respect user's bind preferences by using config.ListenHost
		err := c.SetHTTPAddress(net.JoinHostPort(config.ListenHost, useHTTPPort))
		if err != nil {
			return nil, err
		}
		err = c.SetTLSAddress(net.JoinHostPort(config.ListenHost, ""))
		if err != nil {
			return nil, err
		}
	} else {
		// Otherwise, DNS challenge it is

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
		c.ExcludeChallenges([]acme.Challenge{acme.HTTP01, acme.TLSSNI01})
		c.SetChallengeProvider(acme.DNS01, prov)
	}

	return c, nil
}

// Obtain obtains a single certificate for names. It stores the certificate
// on the disk if successful.
func (c *ACMEClient) Obtain(names []string) error {
Attempts:
	for attempts := 0; attempts < 2; attempts++ {
		namesObtaining.Add(names)
		acmeMu.Lock()
		certificate, failures := c.ObtainCertificate(names, true, nil)
		acmeMu.Unlock()
		namesObtaining.Remove(names)
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
						err := c.AgreeToTOS()
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
		storage, err := c.config.StorageFor(c.config.CAUrl)
		if err != nil {
			return err
		}
		err = saveCertResource(storage, certificate)
		if err != nil {
			return fmt.Errorf("error saving assets for %v: %v", names, err)
		}

		break
	}

	return nil
}

// Renew renews the managed certificate for name. Right now our storage
// mechanism only supports one name per certificate, so this function only
// accepts one domain as input. It can be easily modified to support SAN
// certificates if, one day, they become desperately needed enough that our
// storage mechanism is upgraded to be more complex to support SAN certs.
//
// Anyway, this function is safe for concurrent use.
func (c *ACMEClient) Renew(name string) error {
	// Get access to ACME storage
	storage, err := c.config.StorageFor(c.config.CAUrl)
	if err != nil {
		return err
	}

	// We must lock the renewal with the storage engine
	if lockObtained, err := storage.LockRegister(name); err != nil {
		return err
	} else if !lockObtained {
		log.Printf("[INFO] Certificate for %v is already being renewed elsewhere", name)
		return nil
	}
	defer func() {
		if err := storage.UnlockRegister(name); err != nil {
			log.Printf("[ERROR] Unable to unlock renewal lock for %v: %v", name, err)
		}
	}()

	// Prepare for renewal (load PEM cert, key, and meta)
	siteData, err := storage.LoadSite(name)
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
		newCertMeta, err = c.RenewCertificate(certMeta, true)
		acmeMu.Unlock()
		namesObtaining.Remove([]string{name})
		if err == nil {
			success = true
			break
		}

		// If the legal terms changed and need to be agreed to again,
		// we can handle that.
		if _, ok := err.(acme.TOSError); ok {
			err := c.AgreeToTOS()
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

	return saveCertResource(storage, newCertMeta)
}

// Revoke revokes the certificate for name and deltes
// it from storage.
func (c *ACMEClient) Revoke(name string) error {
	storage, err := c.config.StorageFor(c.config.CAUrl)
	if err != nil {
		return err
	}

	siteExists, err := storage.SiteExists(name)
	if err != nil {
		return err
	}

	if !siteExists {
		return errors.New("no certificate and key for " + name)
	}

	siteData, err := storage.LoadSite(name)
	if err != nil {
		return err
	}

	err = c.Client.RevokeCertificate(siteData.Cert)
	if err != nil {
		return err
	}

	err = storage.DeleteSite(name)
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
