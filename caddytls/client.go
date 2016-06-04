package caddytls

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"os"
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
	storage, err := StorageFor(config.CAUrl)
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
	if u.Scheme != "https" &&
		u.Host != "localhost" &&
		u.Host != "[::1]" &&
		!strings.HasPrefix(u.Host, "127.") &&
		!strings.HasPrefix(u.Host, "10.") {
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
		if caddy.HasListenerWithAddress(net.JoinHostPort(config.ListenHost, HTTPChallengePort)) {
			altPort := config.AltHTTPPort
			if altPort == "" {
				altPort = DefaultHTTPAlternatePort
			}
			c.SetHTTPAddress(net.JoinHostPort(config.ListenHost, altPort))
		}

		// See if TLS challenge needs to be handled by our own facilities
		if caddy.HasListenerWithAddress(net.JoinHostPort(config.ListenHost, TLSSNIChallengePort)) {
			c.SetChallengeProvider(acme.TLSSNI01, tlsSniSolver{})
		}
	} else {
		// Otherwise, DNS challenge it is

		// Load provider constructor function
		provFn, ok := dnsProviders[config.DNSProvider]
		if !ok {
			return nil, errors.New("unknown DNS provider by name '" + config.DNSProvider + "'")
		}

		// we could pass credentials to create the provider, but for now
		// we just let the solver package get them from the environment
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
		acmeMu.Lock()
		certificate, failures := c.ObtainCertificate(names, true, nil)
		acmeMu.Unlock()
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
		storage, err := StorageFor(c.config.CAUrl)
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
	storage, err := StorageFor(c.config.CAUrl)
	if err != nil {
		return err
	}

	// Prepare for renewal (load PEM cert, key, and meta)
	certBytes, err := ioutil.ReadFile(storage.SiteCertFile(name))
	if err != nil {
		return err
	}
	keyBytes, err := ioutil.ReadFile(storage.SiteKeyFile(name))
	if err != nil {
		return err
	}
	metaBytes, err := ioutil.ReadFile(storage.SiteMetaFile(name))
	if err != nil {
		return err
	}
	var certMeta acme.CertificateResource
	err = json.Unmarshal(metaBytes, &certMeta)
	certMeta.Certificate = certBytes
	certMeta.PrivateKey = keyBytes

	// Perform renewal and retry if necessary, but not too many times.
	var newCertMeta acme.CertificateResource
	var success bool
	for attempts := 0; attempts < 2; attempts++ {
		acmeMu.Lock()
		newCertMeta, err = c.RenewCertificate(certMeta, true)
		acmeMu.Unlock()
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
	storage, err := StorageFor(c.config.CAUrl)
	if err != nil {
		return err
	}

	if !existingCertAndKey(storage, name) {
		return errors.New("no certificate and key for " + name)
	}

	certFile := storage.SiteCertFile(name)
	certBytes, err := ioutil.ReadFile(certFile)
	if err != nil {
		return err
	}

	err = c.Client.RevokeCertificate(certBytes)
	if err != nil {
		return err
	}

	err = os.Remove(certFile)
	if err != nil {
		return errors.New("certificate revoked, but unable to delete certificate file: " + err.Error())
	}

	return nil
}
