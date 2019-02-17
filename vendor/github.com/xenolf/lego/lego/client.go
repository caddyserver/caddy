package lego

import (
	"errors"
	"net/url"

	"github.com/xenolf/lego/acme/api"
	"github.com/xenolf/lego/certificate"
	"github.com/xenolf/lego/challenge/resolver"
	"github.com/xenolf/lego/registration"
)

// Client is the user-friendly way to ACME
type Client struct {
	Certificate  *certificate.Certifier
	Challenge    *resolver.SolverManager
	Registration *registration.Registrar
	core         *api.Core
}

// NewClient creates a new ACME client on behalf of the user.
// The client will depend on the ACME directory located at CADirURL for the rest of its actions.
// A private key of type keyType (see KeyType constants) will be generated when requesting a new certificate if one isn't provided.
func NewClient(config *Config) (*Client, error) {
	if config == nil {
		return nil, errors.New("a configuration must be provided")
	}

	_, err := url.Parse(config.CADirURL)
	if err != nil {
		return nil, err
	}

	if config.HTTPClient == nil {
		return nil, errors.New("the HTTP client cannot be nil")
	}

	privateKey := config.User.GetPrivateKey()
	if privateKey == nil {
		return nil, errors.New("private key was nil")
	}

	var kid string
	if reg := config.User.GetRegistration(); reg != nil {
		kid = reg.URI
	}

	core, err := api.New(config.HTTPClient, config.UserAgent, config.CADirURL, kid, privateKey)
	if err != nil {
		return nil, err
	}

	solversManager := resolver.NewSolversManager(core)

	prober := resolver.NewProber(solversManager)
	certifier := certificate.NewCertifier(core, prober, certificate.CertifierOptions{KeyType: config.Certificate.KeyType, Timeout: config.Certificate.Timeout})

	return &Client{
		Certificate:  certifier,
		Challenge:    solversManager,
		Registration: registration.NewRegistrar(core, config.User),
		core:         core,
	}, nil
}

// GetToSURL returns the current ToS URL from the Directory
func (c *Client) GetToSURL() string {
	return c.core.GetDirectory().Meta.TermsOfService
}

// GetExternalAccountRequired returns the External Account Binding requirement of the Directory
func (c *Client) GetExternalAccountRequired() bool {
	return c.core.GetDirectory().Meta.ExternalAccountRequired
}
