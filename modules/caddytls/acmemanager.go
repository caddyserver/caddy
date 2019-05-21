package caddytls

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-acme/lego/certcrypto"

	"bitbucket.org/lightcodelabs/caddy2"
	"github.com/go-acme/lego/challenge"
	"github.com/mholt/certmagic"
)

func init() {
	caddy2.RegisterModule(caddy2.Module{
		Name: "tls.management.acme",
		New:  func() interface{} { return new(acmeManagerMaker) },
	})
}

// acmeManagerMaker makes an ACME manager
// for managinig certificates using ACME.
type acmeManagerMaker struct {
	CA          string           `json:"ca,omitempty"`
	Email       string           `json:"email,omitempty"`
	RenewAhead  caddy2.Duration  `json:"renew_ahead,omitempty"`
	KeyType     string           `json:"key_type,omitempty"`
	ACMETimeout caddy2.Duration  `json:"acme_timeout,omitempty"`
	MustStaple  bool             `json:"must_staple,omitempty"`
	Challenges  ChallengesConfig `json:"challenges"`
	OnDemand    *OnDemandConfig  `json:"on_demand,omitempty"`
	Storage     json.RawMessage  `json:"storage,omitempty"`

	storage certmagic.Storage
	keyType certcrypto.KeyType
}

func (m *acmeManagerMaker) newManager(interactive bool) (certmagic.Manager, error) {
	return nil, nil
}

func (m *acmeManagerMaker) Provision(ctx caddy2.Context) error {
	// DNS providers
	if m.Challenges.DNS != nil {
		val, err := ctx.LoadModuleInline("provider", "tls.dns", m.Challenges.DNS)
		if err != nil {
			return fmt.Errorf("loading TLS storage module: %s", err)
		}
		m.Challenges.dns = val.(challenge.Provider)
		m.Challenges.DNS = nil // allow GC to deallocate - TODO: Does this help?
	}

	// policy-specific storage implementation
	if m.Storage != nil {
		val, err := ctx.LoadModuleInline("system", "caddy.storage", m.Storage)
		if err != nil {
			return fmt.Errorf("loading TLS storage module: %s", err)
		}
		cmStorage, err := val.(caddy2.StorageConverter).CertMagicStorage()
		if err != nil {
			return fmt.Errorf("creating TLS storage configuration: %v", err)
		}
		m.storage = cmStorage
		m.Storage = nil // allow GC to deallocate - TODO: Does this help?
	}

	m.setDefaults()

	return nil
}

// setDefaults sets necessary values that are
// currently empty to their default values.
func (m *acmeManagerMaker) setDefaults() {
	if m.CA == "" {
		m.CA = certmagic.LetsEncryptStagingCA // certmagic.Default.CA // TODO: When not testing, switch to production CA
	}
	if m.Email == "" {
		m.Email = certmagic.Default.Email
	}
	if m.RenewAhead == 0 {
		m.RenewAhead = caddy2.Duration(certmagic.Default.RenewDurationBefore)
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
func (m *acmeManagerMaker) makeCertMagicConfig(ctx caddy2.Context) certmagic.Config {
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
		CA:                      certmagic.LetsEncryptStagingCA, //ap.CA, // TODO: Restore true value
		Email:                   m.Email,
		Agreed:                  true,
		DisableHTTPChallenge:    m.Challenges.HTTP.Disabled,
		DisableTLSALPNChallenge: m.Challenges.TLSALPN.Disabled,
		RenewDurationBefore:     time.Duration(m.RenewAhead),
		AltHTTPPort:             m.Challenges.HTTP.AlternatePort,
		AltTLSALPNPort:          m.Challenges.TLSALPN.AlternatePort,
		DNSProvider:             m.Challenges.dns,
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
