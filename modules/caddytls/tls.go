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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/go-acme/lego/v3/challenge"
	"github.com/mholt/certmagic"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

func init() {
	caddy.RegisterModule(TLS{})
}

// TLS represents a process-wide TLS configuration.
type TLS struct {
	Certificates   map[string]json.RawMessage `json:"certificates,omitempty"`
	Automation     *AutomationConfig          `json:"automation,omitempty"`
	SessionTickets *SessionTicketService      `json:"session_tickets,omitempty"`

	certificateLoaders []CertificateLoader
	certCache          *certmagic.Cache
	ctx                caddy.Context
	storageCleanTicker *time.Ticker
	storageCleanStop   chan struct{}
	logger             *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (TLS) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		Name: "tls",
		New:  func() caddy.Module { return new(TLS) },
	}
}

// Provision sets up the configuration for the TLS app.
func (t *TLS) Provision(ctx caddy.Context) error {
	t.ctx = ctx
	t.logger = ctx.Logger(t)

	// set up a new certificate cache; this (re)loads all certificates
	cacheOpts := certmagic.CacheOptions{
		GetConfigForCert: func(cert certmagic.Certificate) (certmagic.Config, error) {
			return t.getConfigForName(cert.Names[0])
		},
	}
	if t.Automation != nil {
		cacheOpts.OCSPCheckInterval = time.Duration(t.Automation.OCSPCheckInterval)
		cacheOpts.RenewCheckInterval = time.Duration(t.Automation.RenewCheckInterval)
	}
	t.certCache = certmagic.NewCache(cacheOpts)

	// automation/management policies
	if t.Automation != nil {
		for i, ap := range t.Automation.Policies {
			val, err := ctx.LoadModuleInline("module", "tls.management", ap.ManagementRaw)
			if err != nil {
				return fmt.Errorf("loading TLS automation management module: %s", err)
			}
			t.Automation.Policies[i].Management = val.(ManagerMaker)
			t.Automation.Policies[i].ManagementRaw = nil // allow GC to deallocate
		}
	}

	// certificate loaders
	for modName, rawMsg := range t.Certificates {
		if modName == automateKey {
			continue // special case; these will be loaded in later
		}
		val, err := ctx.LoadModule("tls.certificates."+modName, rawMsg)
		if err != nil {
			return fmt.Errorf("loading certificate module '%s': %s", modName, err)
		}
		t.certificateLoaders = append(t.certificateLoaders, val.(CertificateLoader))
	}

	// session ticket ephemeral keys (STEK) service and provider
	if t.SessionTickets != nil {
		err := t.SessionTickets.provision(ctx)
		if err != nil {
			return fmt.Errorf("provisioning session tickets configuration: %v", err)
		}
	}

	// on-demand rate limiting
	if t.Automation != nil && t.Automation.OnDemand != nil && t.Automation.OnDemand.RateLimit != nil {
		onDemandRateLimiter.SetMaxEvents(t.Automation.OnDemand.RateLimit.Burst)
		onDemandRateLimiter.SetWindow(time.Duration(t.Automation.OnDemand.RateLimit.Interval))
	} else {
		// remove any existing rate limiter
		onDemandRateLimiter.SetMaxEvents(0)
		onDemandRateLimiter.SetWindow(0)
	}

	// load manual/static (unmanaged) certificates - we do this in
	// provision so that other apps (such as http) can know which
	// certificates have been manually loaded
	magic := certmagic.New(t.certCache, certmagic.Config{
		Storage: ctx.Storage(),
	})
	for _, loader := range t.certificateLoaders {
		certs, err := loader.LoadCertificates()
		if err != nil {
			return fmt.Errorf("loading certificates: %v", err)
		}
		for _, cert := range certs {
			err := magic.CacheUnmanagedTLSCertificate(cert.Certificate, cert.Tags)
			if err != nil {
				return fmt.Errorf("caching unmanaged certificate: %v", err)
			}
		}
	}

	return nil
}

// Start activates the TLS module.
func (t *TLS) Start() error {
	// load automated (managed) certificates
	if automatedRawMsg, ok := t.Certificates[automateKey]; ok {
		var names []string
		err := json.Unmarshal(automatedRawMsg, &names)
		if err != nil {
			return fmt.Errorf("automate: decoding names: %v", err)
		}
		err = t.Manage(names)
		if err != nil {
			return fmt.Errorf("automate: managing %v: %v", names, err)
		}
	}
	t.Certificates = nil // allow GC to deallocate

	t.keepStorageClean()

	return nil
}

// Stop stops the TLS module and cleans up any allocations.
func (t *TLS) Stop() error {
	// stop the storage cleaner goroutine and ticker
	if t.storageCleanStop != nil {
		close(t.storageCleanStop)
	}
	if t.storageCleanTicker != nil {
		t.storageCleanTicker.Stop()
	}
	return nil
}

// Cleanup frees up resources allocated during Provision.
func (t *TLS) Cleanup() error {
	// stop the certificate cache
	if t.certCache != nil {
		t.certCache.Stop()
	}

	// stop the session ticket rotation goroutine
	if t.SessionTickets != nil {
		t.SessionTickets.stop()
	}

	return nil
}

// Manage immediately begins managing names according to the
// matching automation policy.
func (t *TLS) Manage(names []string) error {
	for _, name := range names {
		ap := t.getAutomationPolicyForName(name)
		magic := certmagic.New(t.certCache, ap.makeCertMagicConfig(t.ctx))
		var err error
		if ap.ManageSync {
			err = magic.ManageSync([]string{name})
		} else {
			err = magic.ManageAsync(t.ctx.Context, []string{name})
		}
		if err != nil {
			return fmt.Errorf("automate: manage %s: %v", name, err)
		}
	}
	return nil
}

// HandleHTTPChallenge ensures that the HTTP challenge is handled for the
// certificate named by r.Host, if it is an HTTP challenge request.
func (t *TLS) HandleHTTPChallenge(w http.ResponseWriter, r *http.Request) bool {
	if !certmagic.LooksLikeHTTPChallenge(r) {
		return false
	}
	ap := t.getAutomationPolicyForName(r.Host)
	magic := certmagic.New(t.certCache, ap.makeCertMagicConfig(t.ctx))
	return magic.HandleHTTPChallenge(w, r)
}

func (t *TLS) getConfigForName(name string) (certmagic.Config, error) {
	ap := t.getAutomationPolicyForName(name)
	return ap.makeCertMagicConfig(t.ctx), nil
}

func (t *TLS) getAutomationPolicyForName(name string) AutomationPolicy {
	if t.Automation != nil {
		for _, ap := range t.Automation.Policies {
			if len(ap.Hosts) == 0 {
				// no host filter is an automatic match
				return ap
			}
			for _, h := range ap.Hosts {
				if h == name {
					return ap
				}
			}
		}
	}

	// default automation policy
	return AutomationPolicy{Management: new(ACMEManagerMaker)}
}

// AllMatchingCertificates returns the list of all certificates in
// the cache which could be used to satisfy the given SAN.
func (t *TLS) AllMatchingCertificates(san string) []certmagic.Certificate {
	return t.certCache.AllMatchingCertificates(san)
}

// keepStorageClean immediately cleans up all known storage units
// if it was not recently done, and starts a goroutine that runs
// the operation at every tick from t.storageCleanTicker.
func (t *TLS) keepStorageClean() {
	t.storageCleanTicker = time.NewTicker(storageCleanInterval)
	t.storageCleanStop = make(chan struct{})
	go func() {
		for {
			select {
			case <-t.storageCleanStop:
				return
			case <-t.storageCleanTicker.C:
				t.cleanStorageUnits()
			}
		}
	}()
	t.cleanStorageUnits()
}

func (t *TLS) cleanStorageUnits() {
	storageCleanMu.Lock()
	defer storageCleanMu.Unlock()

	if !storageClean.IsZero() && time.Since(storageClean) < storageCleanInterval {
		return
	}

	options := certmagic.CleanStorageOptions{
		OCSPStaples:            true,
		ExpiredCerts:           true,
		ExpiredCertGracePeriod: 24 * time.Hour * 14,
	}

	// start with the default storage
	certmagic.CleanStorage(t.ctx.Storage(), options)

	// then clean each storage defined in ACME automation policies
	if t.Automation != nil {
		for _, ap := range t.Automation.Policies {
			if acmeMgmt, ok := ap.Management.(ACMEManagerMaker); ok {
				if acmeMgmt.storage != nil {
					certmagic.CleanStorage(acmeMgmt.storage, options)
				}
			}
		}
	}

	storageClean = time.Now()

	t.logger.Info("cleaned up storage units")
}

// CertificateLoader is a type that can load certificates.
// Certificates can optionally be associated with tags.
type CertificateLoader interface {
	LoadCertificates() ([]Certificate, error)
}

// Certificate is a TLS certificate, optionally
// associated with arbitrary tags.
type Certificate struct {
	tls.Certificate
	Tags []string
}

// AutomationConfig designates configuration for the
// construction and use of ACME clients.
type AutomationConfig struct {
	Policies           []AutomationPolicy `json:"policies,omitempty"`
	OnDemand           *OnDemandConfig    `json:"on_demand,omitempty"`
	OCSPCheckInterval  caddy.Duration     `json:"ocsp_interval,omitempty"`
	RenewCheckInterval caddy.Duration     `json:"renew_interval,omitempty"`
}

// AutomationPolicy designates the policy for automating the
// management of managed TLS certificates.
type AutomationPolicy struct {
	Hosts         []string        `json:"hosts,omitempty"`
	ManagementRaw json.RawMessage `json:"management,omitempty"`
	ManageSync    bool            `json:"manage_sync,omitempty"`

	Management ManagerMaker `json:"-"`
}

// makeCertMagicConfig converts ap into a CertMagic config. Passing onDemand
// is necessary because the automation policy does not have convenient access
// to the TLS app's global on-demand policies;
func (ap AutomationPolicy) makeCertMagicConfig(ctx caddy.Context) certmagic.Config {
	// default manager (ACME) is a special case because of how CertMagic is designed
	// TODO: refactor certmagic so that ACME manager is not a special case by extracting
	// its config fields out of the certmagic.Config struct, or something...
	if acmeMgmt, ok := ap.Management.(*ACMEManagerMaker); ok {
		return acmeMgmt.makeCertMagicConfig(ctx)
	}

	return certmagic.Config{
		NewManager: ap.Management.NewManager,
	}
}

// ChallengesConfig configures the ACME challenges.
type ChallengesConfig struct {
	HTTP    *HTTPChallengeConfig    `json:"http,omitempty"`
	TLSALPN *TLSALPNChallengeConfig `json:"tls-alpn,omitempty"`
	DNSRaw  json.RawMessage         `json:"dns,omitempty"`

	DNS challenge.Provider `json:"-"`
}

// HTTPChallengeConfig configures the ACME HTTP challenge.
type HTTPChallengeConfig struct {
	Disabled      bool `json:"disabled,omitempty"`
	AlternatePort int  `json:"alternate_port,omitempty"`
}

// TLSALPNChallengeConfig configures the ACME TLS-ALPN challenge.
type TLSALPNChallengeConfig struct {
	Disabled      bool `json:"disabled,omitempty"`
	AlternatePort int  `json:"alternate_port,omitempty"`
}

// OnDemandConfig configures on-demand TLS, for obtaining
// needed certificates at handshake-time.
type OnDemandConfig struct {
	RateLimit *RateLimit `json:"rate_limit,omitempty"`
	Ask       string     `json:"ask,omitempty"`
}

// RateLimit specifies an interval with optional burst size.
type RateLimit struct {
	Interval caddy.Duration `json:"interval,omitempty"`
	Burst    int            `json:"burst,omitempty"`
}

// ManagerMaker makes a certificate manager.
type ManagerMaker interface {
	NewManager(interactive bool) (certmagic.Manager, error)
}

// These perpetual values are used for on-demand TLS.
var (
	onDemandRateLimiter = certmagic.NewRateLimiter(0, 0)
	onDemandAskClient   = &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return fmt.Errorf("following http redirects is not allowed")
		},
	}
)

// Variables related to storage cleaning.
var (
	storageCleanInterval = 12 * time.Hour

	storageClean   time.Time
	storageCleanMu sync.Mutex
)

// Interface guards
var (
	_ caddy.App          = (*TLS)(nil)
	_ caddy.Provisioner  = (*TLS)(nil)
	_ caddy.CleanerUpper = (*TLS)(nil)
)

const automateKey = "automate"
