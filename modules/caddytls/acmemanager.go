package caddytls

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-acme/lego/certcrypto"

	"github.com/caddyserver/caddy"
	"github.com/go-acme/lego/challenge"
	"github.com/mholt/certmagic"
)

func init() {
	caddy.RegisterModule(caddy.Module{
		Name: "tls.management.acme",
		New:  func() interface{} { return new(ACMEManagerMaker) },
	})
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
	RenewAhead  caddy.Duration  `json:"renew_ahead,omitempty"`
	KeyType     string           `json:"key_type,omitempty"`
	ACMETimeout caddy.Duration  `json:"acme_timeout,omitempty"`
	MustStaple  bool             `json:"must_staple,omitempty"`
	Challenges  ChallengesConfig `json:"challenges"`
	OnDemand    *OnDemandConfig  `json:"on_demand,omitempty"`
	Storage     json.RawMessage  `json:"storage,omitempty"`

	storage certmagic.Storage
	keyType certcrypto.KeyType
}

// newManager is a no-op to satisfy the ManagerMaker interface,
// because this manager type is a special case.
func (m *ACMEManagerMaker) newManager(interactive bool) (certmagic.Manager, error) {
	return nil, nil
}

// Provision sets up m.
func (m *ACMEManagerMaker) Provision(ctx caddy.Context) error {
	// DNS providers
	if m.Challenges.DNS != nil {
		val, err := ctx.LoadModuleInline("provider", "tls.dns", m.Challenges.DNSRaw)
		if err != nil {
			return fmt.Errorf("loading TLS storage module: %s", err)
		}
		m.Challenges.DNS = val.(challenge.Provider)
		m.Challenges.DNSRaw = nil // allow GC to deallocate - TODO: Does this help?
	}

	// policy-specific storage implementation
	if m.Storage != nil {
		val, err := ctx.LoadModuleInline("system", "caddy.storage", m.Storage)
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
	if m.CA == "" {
		m.CA = certmagic.LetsEncryptStagingCA // certmagic.Default.CA // TODO: When not testing, switch to production CA
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
	if m.OnDemand != nil {
		ond = &certmagic.OnDemandConfig{
			// TODO: fill this out
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

// supportedCertKeyTypes is all the key types that are supported
// for certificates that are obtained through ACME.
var supportedCertKeyTypes = map[string]certcrypto.KeyType{
	"RSA2048": certcrypto.RSA2048,
	"RSA4096": certcrypto.RSA4096,
	"P256":    certcrypto.EC256,
	"P384":    certcrypto.EC384,
}

// Interface guard
var _ managerMaker = (*ACMEManagerMaker)(nil)
