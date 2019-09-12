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
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/go-acme/lego/certcrypto"

	"github.com/caddyserver/caddy/v2"
	"github.com/go-acme/lego/challenge"
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
	CA          string           `json:"ca,omitempty"`
	Email       string           `json:"email,omitempty"`
	RenewAhead  caddy.Duration   `json:"renew_ahead,omitempty"`
	KeyType     string           `json:"key_type,omitempty"`
	ACMETimeout caddy.Duration   `json:"acme_timeout,omitempty"`
	MustStaple  bool             `json:"must_staple,omitempty"`
	Challenges  ChallengesConfig `json:"challenges,omitempty"`
	OnDemand    bool             `json:"on_demand,omitempty"`
	Storage     json.RawMessage  `json:"storage,omitempty"`

	storage certmagic.Storage
	keyType certcrypto.KeyType
}

// CaddyModule returns the Caddy module information.
func (ACMEManagerMaker) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		Name: "tls.management.acme",
		New:  func() caddy.Module { return new(ACMEManagerMaker) },
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
	if m.Challenges.DNSRaw != nil {
		val, err := ctx.LoadModuleInline("provider", "tls.dns", m.Challenges.DNSRaw)
		if err != nil {
			return fmt.Errorf("loading DNS provider module: %s", err)
		}
		m.Challenges.DNS = val.(challenge.Provider)
		m.Challenges.DNSRaw = nil // allow GC to deallocate - TODO: Does this help?
	}

	// policy-specific storage implementation
	if m.Storage != nil {
		val, err := ctx.LoadModuleInline("module", "caddy.storage", m.Storage)
		if err != nil {
			return fmt.Errorf("loading TLS storage module: %s", err)
		}
		cmStorage, err := val.(caddy.StorageConverter).CertMagicStorage()
		if err != nil {
			return fmt.Errorf("creating TLS storage configuration: %v", err)
		}
		m.storage = cmStorage
		m.Storage = nil // allow GC to deallocate - TODO: Does this help?
	}

	m.SetDefaults()

	return nil
}

// SetDefaults sets necessary values that are
// currently empty to their default values.
func (m *ACMEManagerMaker) SetDefaults() {
	// TODO: Setting all these defaults might not be necessary
	// since CertMagic should fill them in for us...
	if m.CA == "" {
		m.CA = certmagic.Default.CA
	}
	if m.Email == "" {
		m.Email = certmagic.Default.Email
	}
	if m.RenewAhead == 0 {
		m.RenewAhead = caddy.Duration(certmagic.Default.RenewDurationBefore)
	}
	if m.keyType == "" {
		m.keyType = certmagic.Default.KeyType
	}
	if m.storage == nil {
		m.storage = certmagic.Default.Storage
	}
}

// makeCertMagicConfig converts m into a certmagic.Config, because
// this is a special case where the default manager is the certmagic
// Config and not a separate manager.
func (m *ACMEManagerMaker) makeCertMagicConfig(ctx caddy.Context) certmagic.Config {
	storage := m.storage
	if storage == nil {
		storage = ctx.Storage()
	}

	var ond *certmagic.OnDemandConfig
	if m.OnDemand {
		var onDemand *OnDemandConfig
		appVal, err := ctx.App("tls")
		if err == nil {
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
					// check the rate limiter last, since
					// even checking consumes a token; so
					// don't even bother checking if the
					// other regulations fail anyway
					if onDemand.RateLimit != nil {
						if !onDemandRateLimiter.Allow() {
							return fmt.Errorf("on-demand rate limit exceeded")
						}
					}
				}
				return nil
			},
		}
	}

	return certmagic.Config{
		CA:                      m.CA,
		Email:                   m.Email,
		Agreed:                  true,
		DisableHTTPChallenge:    m.Challenges.HTTP.Disabled,
		DisableTLSALPNChallenge: m.Challenges.TLSALPN.Disabled,
		RenewDurationBefore:     time.Duration(m.RenewAhead),
		AltHTTPPort:             m.Challenges.HTTP.AlternatePort,
		AltTLSALPNPort:          m.Challenges.TLSALPN.AlternatePort,
		DNSProvider:             m.Challenges.DNS,
		KeyType:                 supportedCertKeyTypes[m.KeyType],
		CertObtainTimeout:       time.Duration(m.ACMETimeout),
		OnDemand:                ond,
		MustStaple:              m.MustStaple,
		Storage:                 storage,
		// TODO: listenHost
	}
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
