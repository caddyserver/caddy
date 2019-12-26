// Copyright 2015 Matthew Holt and The Caddy Authors
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
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/url"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/go-acme/lego/v3/challenge"
	"github.com/mholt/certmagic"
)

func init() {
	caddy.RegisterModule(ACMEManagerMaker{})
}

// ACMEManagerMaker makes an ACME manager
// for managing certificates using ACME.
// If crafting one manually rather than
// through the config-unmarshal process
// (provisioning), be sure to call
// SetDefaults to ensure sane defaults
// after you have configured this struct
// to your liking.
type ACMEManagerMaker struct {
	// The URL to the CA's ACME directory endpoint.
	CA string `json:"ca,omitempty"`

	// Your email address, so the CA can contact you if necessary.
	// Not required, but strongly recommended to provide one so
	// you can be reached if there is a problem. Your email is
	// not sent to any Caddy mothership or used for any purpose
	// other than ACME transactions.
	Email string `json:"email,omitempty"`

	// How long before a certificate's expiration to try renewing it.
	// Should usually be about 1/3 of certificate lifetime, but long
	// enough to give yourself time to troubleshoot problems before
	// expiration. Default: 30d
	RenewAhead caddy.Duration `json:"renew_ahead,omitempty"`

	// The type of key to generate for the certificate.
	// Supported values: `rsa2048`, `rsa4096`, `p256`, `p384`.
	KeyType string `json:"key_type,omitempty"`

	// Time to wait before timing out an ACME operation.
	ACMETimeout caddy.Duration `json:"acme_timeout,omitempty"`

	// If true, certificates will be requested with MustStaple. Not all
	// CAs support this, and there are potentially serious consequences
	// of enabling this feature without proper threat modeling.
	MustStaple bool `json:"must_staple,omitempty"`

	// Configures the various ACME challenge types.
	Challenges *ChallengesConfig `json:"challenges,omitempty"`

	// If true, certificates will be managed "on demand", that is, during
	// TLS handshakes or when needed, as opposed to at startup or config
	// load.
	OnDemand bool `json:"on_demand,omitempty"`

	// Optionally configure a separate storage module associated with this
	// manager, instead of using Caddy's global/default-configured storage.
	Storage json.RawMessage `json:"storage,omitempty"`

	// An array of files of CA certificates to accept when connecting to the
	// ACME CA. Generally, you should only use this if the ACME CA endpoint
	// is internal or for development/testing purposes.
	TrustedRootsPEMFiles []string `json:"trusted_roots_pem_files,omitempty"`

	storage  certmagic.Storage
	rootPool *x509.CertPool
}

// CaddyModule returns the Caddy module information.
func (ACMEManagerMaker) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.management.acme",
		New: func() caddy.Module { return new(ACMEManagerMaker) },
	}
}

// NewManager is a no-op to satisfy the ManagerMaker interface,
// because this manager type is a special case.
func (m ACMEManagerMaker) NewManager(interactive bool) (certmagic.Manager, error) {
	return nil, nil
}

// Provision sets up m.
func (m *ACMEManagerMaker) Provision(ctx caddy.Context) error {
	// DNS providers
	if m.Challenges != nil && m.Challenges.DNSRaw != nil {
		val, err := ctx.LoadModule(m.Challenges, "DNSRaw")
		if err != nil {
			return fmt.Errorf("loading DNS provider module: %v", err)
		}
		m.Challenges.DNS = val.(challenge.Provider)
	}

	// policy-specific storage implementation
	if m.Storage != nil {
		val, err := ctx.LoadModule(m, "Storage")
		if err != nil {
			return fmt.Errorf("loading TLS storage module: %v", err)
		}
		cmStorage, err := val.(caddy.StorageConverter).CertMagicStorage()
		if err != nil {
			return fmt.Errorf("creating TLS storage configuration: %v", err)
		}
		m.storage = cmStorage
	}

	// add any custom CAs to trust store
	if len(m.TrustedRootsPEMFiles) > 0 {
		m.rootPool = x509.NewCertPool()
		for _, pemFile := range m.TrustedRootsPEMFiles {
			pemData, err := ioutil.ReadFile(pemFile)
			if err != nil {
				return fmt.Errorf("loading trusted root CA's PEM file: %s: %v", pemFile, err)
			}
			if !m.rootPool.AppendCertsFromPEM(pemData) {
				return fmt.Errorf("unable to add %s to trust pool: %v", pemFile, err)
			}
		}
	}

	return nil
}

// makeCertMagicConfig converts m into a certmagic.Config, because
// this is a special case where the default manager is the certmagic
// Config and not a separate manager.
func (m *ACMEManagerMaker) makeCertMagicConfig(ctx caddy.Context) certmagic.Config {
	storage := m.storage
	if storage == nil {
		storage = ctx.Storage()
	}

	if m.CA == "ca.local" {
		return certmagic.Config{
			NewManager: func(interactive bool) (certmagic.Manager, error) {
				m.storage = storage
				return NewSmallStepManager(m)
			},
		}
	}

	var ond *certmagic.OnDemandConfig
	if m.OnDemand {
		var onDemand *OnDemandConfig
		appVal, err := ctx.App("tls")
		if err == nil && appVal.(*TLS).Automation != nil {
			onDemand = appVal.(*TLS).Automation.OnDemand
		}

		ond = &certmagic.OnDemandConfig{
			DecisionFunc: func(name string) error {
				if onDemand != nil {
					if onDemand.Ask != "" {
						err := onDemandAskRequest(onDemand.Ask, name)
						if err != nil {
							return err
						}
					}
					// check the rate limiter last because
					// doing so makes a reservation
					if !onDemandRateLimiter.Allow() {
						return fmt.Errorf("on-demand rate limit exceeded")
					}
				}
				return nil
			},
		}
	}

	cfg := certmagic.Config{
		CA:                  m.CA,
		Email:               m.Email,
		Agreed:              true,
		RenewDurationBefore: time.Duration(m.RenewAhead),
		KeyType:             supportedCertKeyTypes[m.KeyType],
		CertObtainTimeout:   time.Duration(m.ACMETimeout),
		OnDemand:            ond,
		MustStaple:          m.MustStaple,
		Storage:             storage,
		TrustedRoots:        m.rootPool,
		// TODO: listenHost
	}

	if m.Challenges != nil {
		if m.Challenges.HTTP != nil {
			cfg.DisableHTTPChallenge = m.Challenges.HTTP.Disabled
			cfg.AltHTTPPort = m.Challenges.HTTP.AlternatePort
		}
		if m.Challenges.TLSALPN != nil {
			cfg.DisableTLSALPNChallenge = m.Challenges.TLSALPN.Disabled
			cfg.AltTLSALPNPort = m.Challenges.TLSALPN.AlternatePort
		}
		cfg.DNSProvider = m.Challenges.DNS
	}

	return cfg
}

// onDemandAskRequest makes a request to the ask URL
// to see if a certificate can be obtained for name.
// The certificate request should be denied if this
// returns an error.
func onDemandAskRequest(ask string, name string) error {
	askURL, err := url.Parse(ask)
	if err != nil {
		return fmt.Errorf("parsing ask URL: %v", err)
	}
	qs := askURL.Query()
	qs.Set("domain", name)
	askURL.RawQuery = qs.Encode()

	resp, err := onDemandAskClient.Get(askURL.String())
	if err != nil {
		return fmt.Errorf("error checking %v to deterine if certificate for hostname '%s' should be allowed: %v",
			ask, name, err)
	}
	resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("certificate for hostname '%s' not allowed; non-2xx status code %d returned from %v",
			name, resp.StatusCode, ask)
	}

	return nil
}

// Interface guard
var _ ManagerMaker = (*ACMEManagerMaker)(nil)
