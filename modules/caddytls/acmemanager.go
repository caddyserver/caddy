package caddytls

import (
	"encoding/json"
	"fmt"

	"github.com/go-acme/lego/certcrypto"

	"bitbucket.org/lightcodelabs/caddy2"
	"github.com/go-acme/lego/challenge"
	"github.com/mholt/certmagic"
)

func init() {
	caddy2.RegisterModule(caddy2.Module{
		Name: "tls.management.acme",
		New:  func() (interface{}, error) { return new(acmeManagerMaker), nil },
	})
}

// ManagerMaker TODO: WIP...
type ManagerMaker interface {
	newManager(interactive bool) (certmagic.Manager, error)
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

func (m *acmeManagerMaker) Provision() error {
	m.setDefaults()

	// DNS providers
	if m.Challenges.DNS != nil {
		val, err := caddy2.LoadModuleInline("provider", "tls.dns", m.Challenges.DNS)
		if err != nil {
			return fmt.Errorf("loading TLS storage module: %s", err)
		}
		m.Challenges.dns = val.(challenge.Provider)
		m.Challenges.DNS = nil // allow GC to deallocate - TODO: Does this help?
	}

	// policy-specific storage implementation
	if m.Storage != nil {
		val, err := caddy2.LoadModuleInline("system", "caddy.storage", m.Storage)
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

	return nil
}

// setDefaults indiscriminately sets all the default values in m.
func (m *acmeManagerMaker) setDefaults() {
	m.CA = certmagic.LetsEncryptStagingCA // certmagic.Default.CA // TODO: When not testing, switch to production CA
	m.Email = certmagic.Default.Email
	m.RenewAhead = caddy2.Duration(certmagic.Default.RenewDurationBefore)
	m.keyType = certmagic.Default.KeyType
	m.storage = certmagic.Default.Storage
}

func (m *acmeManagerMaker) newManager(interactive bool) (certmagic.Manager, error) {
	return nil, nil
}
