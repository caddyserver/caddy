package https

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"sync"
	"time"

	"github.com/mholt/caddy/server"
	"github.com/xenolf/lego/acme"
)

// acmeMu ensures that only one ACME challenge occurs at a time.
var acmeMu sync.Mutex

// ACMEClient is an acme.Client with custom state attached.
type ACMEClient struct {
	*acme.Client
	AllowPrompts bool // if false, we assume AlternatePort must be used
}

// NewACMEClient creates a new ACMEClient given an email and whether
// prompting the user is allowed. Clients should not be kept and
// re-used over long periods of time, but immediate re-use is more
// efficient than re-creating on every iteration.
var NewACMEClient = func(email string, allowPrompts bool) (*ACMEClient, error) {
	// Look up or create the LE user account
	leUser, err := getUser(email)
	if err != nil {
		return nil, err
	}

	// The client facilitates our communication with the CA server.
	client, err := acme.NewClient(CAUrl, &leUser, KeyType)
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
			saveUser(leUser) // Might as well try, right?
			return nil, errors.New("error agreeing to terms: " + err.Error())
		}

		// save user to the file system
		err = saveUser(leUser)
		if err != nil {
			return nil, errors.New("could not save user: " + err.Error())
		}
	}

	return &ACMEClient{
		Client:       client,
		AllowPrompts: allowPrompts,
	}, nil
}

// NewACMEClientGetEmail creates a new ACMEClient and gets an email
// address at the same time (a server config is required, since it
// may contain an email address in it).
func NewACMEClientGetEmail(config server.Config, allowPrompts bool) (*ACMEClient, error) {
	return NewACMEClient(getEmail(config, allowPrompts), allowPrompts)
}

// Configure configures c according to bindHost, which is the host (not
// whole address) to bind the listener to in solving the http and tls-sni
// challenges.
func (c *ACMEClient) Configure(bindHost string) {
	// If we allow prompts, operator must be present. In our case,
	// that is synonymous with saying the server is not already
	// started. So if the user is still there, we don't use
	// AlternatePort because we don't need to proxy the challenges.
	// Conversely, if the operator is not there, the server has
	// already started and we need to proxy the challenge.
	if c.AllowPrompts {
		// Operator is present; server is not already listening
		c.SetHTTPAddress(net.JoinHostPort(bindHost, ""))
		c.SetTLSAddress(net.JoinHostPort(bindHost, ""))
		//c.ExcludeChallenges([]acme.Challenge{acme.DNS01})
	} else {
		// Operator is not present; server is started, so proxy challenges
		c.SetHTTPAddress(net.JoinHostPort(bindHost, AlternatePort))
		c.SetTLSAddress(net.JoinHostPort(bindHost, AlternatePort))
		//c.ExcludeChallenges([]acme.Challenge{acme.TLSSNI01, acme.DNS01})
	}
	c.ExcludeChallenges([]acme.Challenge{acme.TLSSNI01, acme.DNS01}) // TODO: can we proxy TLS challenges? and we should support DNS...
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
				// TODO: Double-check, will obtainErr ever be nil?
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
		err := saveCertResource(certificate)
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
		time.Sleep(10 * time.Second)
	}

	if !success {
		return errors.New("too many renewal attempts; last error: " + err.Error())
	}

	return saveCertResource(newCertMeta)
}
