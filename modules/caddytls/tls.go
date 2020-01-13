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
)

func init() {
	caddy.RegisterModule(TLS{})
	caddy.RegisterModule(AutomateLoader{})
}

// TLS provides TLS facilities including certificate
// loading and management, client auth, and more.
type TLS struct {
	// Caches certificates in memory for quick use during
	// TLS handshakes. Each key is the name of a certificate
	// loader module. All loaded certificates get pooled
	// into the same cache and may be used to complete TLS
	// handshakes for the relevant server names (SNI).
	// Certificates loaded manually (anything other than
	// "automate") are not automatically managed and will
	// have to be refreshed manually before they expire.
	CertificatesRaw caddy.ModuleMap `json:"certificates,omitempty" caddy:"namespace=tls.certificates"`

	// Configures the automation of certificate management.
	Automation *AutomationConfig `json:"automation,omitempty"`

	// Configures session ticket ephemeral keys (STEKs).
	SessionTickets *SessionTicketService `json:"session_tickets,omitempty"`

	certificateLoaders []CertificateLoader
	automateNames      []string
	certCache          *certmagic.Cache
	ctx                caddy.Context
	storageCleanTicker *time.Ticker
	storageCleanStop   chan struct{}
	logger             *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (TLS) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls",
		New: func() caddy.Module { return new(TLS) },
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
			val, err := ctx.LoadModule(&ap, "ManagementRaw")
			if err != nil {
				return fmt.Errorf("loading TLS automation management module: %s", err)
			}
			t.Automation.Policies[i].Management = val.(ManagerMaker)
		}
	}

	// certificate loaders
	val, err := ctx.LoadModule(t, "CertificatesRaw")
	if err != nil {
		return fmt.Errorf("loading TLS automation management module: %s", err)
	}
	for modName, modIface := range val.(map[string]interface{}) {
		if modName == "automate" {
			// special case; these will be loaded in later
			// using our automation facilities, which we
			// want to avoid during provisioning
			if automateNames, ok := modIface.(*AutomateLoader); ok && automateNames != nil {
				t.automateNames = []string(*automateNames)
			} else {
				return fmt.Errorf("loading certificates with 'automate' requires array of strings, got: %T", modIface)
			}
			continue
		}
		t.certificateLoaders = append(t.certificateLoaders, modIface.(CertificateLoader))
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
	// certificates have been manually loaded, and also so that
	// commands like validate can be a better test
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
	// now that we are running, and all manual certificates have
	// been loaded, time to load the automated/managed certificates
	err := t.Manage(t.automateNames)
	if err != nil {
		return fmt.Errorf("automate: managing %v: %v", t.automateNames, err)
	}

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
	// The list of automation policies. The first matching
	// policy will be applied for a given certificate/name.
	Policies []AutomationPolicy `json:"policies,omitempty"`

	// On-Demand TLS defers certificate operations to the
	// moment they are needed, e.g. during a TLS handshake.
	// Useful when you don't know all the hostnames up front.
	// Caddy was the first web server to deploy this technology.
	OnDemand *OnDemandConfig `json:"on_demand,omitempty"`

	// Caddy staples OCSP (and caches the response) for all
	// qualifying certificates by default. This setting
	// changes how often it scans responses for freshness,
	// and updates them if they are getting stale.
	OCSPCheckInterval caddy.Duration `json:"ocsp_interval,omitempty"`

	// Every so often, Caddy will scan all loaded, managed
	// certificates for expiration. Certificates which are
	// about 2/3 into their valid lifetime are due for
	// renewal. This setting changes how frequently the scan
	// is performed. If your certificate lifetimes are very
	// short (less than ~1 week), you should customize this.
	RenewCheckInterval caddy.Duration `json:"renew_interval,omitempty"`
}

// AutomationPolicy designates the policy for automating the
// management (obtaining, renewal, and revocation) of managed
// TLS certificates.
type AutomationPolicy struct {
	// Which hostnames this policy applies to.
	Hosts []string `json:"hosts,omitempty"`

	// How to manage certificates.
	ManagementRaw json.RawMessage `json:"management,omitempty" caddy:"namespace=tls.management inline_key=module"`

	// If true, certificate management will be conducted
	// in the foreground; this will block config reloads
	// and return errors if there were problems with
	// obtaining or renewing certificates. This is often
	// not desirable, especially when serving sites out
	// of your control. Default: false
	ManageSync bool `json:"manage_sync,omitempty"`

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
	// HTTP configures the ACME HTTP challenge. This
	// challenge is enabled and used automatically
	// and by default.
	HTTP *HTTPChallengeConfig `json:"http,omitempty"`

	// TLSALPN configures the ACME TLS-ALPN challenge.
	// This challenge is enabled and used automatically
	// and by default.
	TLSALPN *TLSALPNChallengeConfig `json:"tls-alpn,omitempty"`

	// Configures the ACME DNS challenge. Because this
	// challenge typically requires credentials for
	// interfacing with a DNS provider, this challenge is
	// not enabled by default. This is the only challenge
	// type which does not require a direct connection
	// to Caddy from an external server.
	DNSRaw json.RawMessage `json:"dns,omitempty" caddy:"namespace=tls.dns inline_key=provider"`

	DNS challenge.Provider `json:"-"`
}

// HTTPChallengeConfig configures the ACME HTTP challenge.
type HTTPChallengeConfig struct {
	// If true, the HTTP challenge will be disabled.
	Disabled bool `json:"disabled,omitempty"`

	// An alternate port on which to service this
	// challenge. Note that the HTTP challenge port is
	// hard-coded into the spec and cannot be changed,
	// so you would have to forward packets from the
	// standard HTTP challenge port to this one.
	AlternatePort int `json:"alternate_port,omitempty"`
}

// TLSALPNChallengeConfig configures the ACME TLS-ALPN challenge.
type TLSALPNChallengeConfig struct {
	// If true, the TLS-ALPN challenge will be disabled.
	Disabled bool `json:"disabled,omitempty"`

	// An alternate port on which to service this
	// challenge. Note that the TLS-ALPN challenge port
	// is hard-coded into the spec and cannot be changed,
	// so you would have to forward packets from the
	// standard TLS-ALPN challenge port to this one.
	AlternatePort int `json:"alternate_port,omitempty"`
}

// OnDemandConfig configures on-demand TLS, for obtaining
// needed certificates at handshake-time. Because this
// feature can easily be abused, you should set up rate
// limits and/or an internal endpoint that Caddy can
// "ask" if it should be allowed to manage certificates
// for a given hostname.
type OnDemandConfig struct {
	// An optional rate limit to throttle the
	// issuance of certificates from handshakes.
	RateLimit *RateLimit `json:"rate_limit,omitempty"`

	// If Caddy needs to obtain or renew a certificate
	// during a TLS handshake, it will perform a quick
	// HTTP request to this URL to check if it should be
	// allowed to try to get a certificate for the name
	// in the "domain" query string parameter, like so:
	// `?domain=example.com`. The endpoint must return a
	// 200 OK status if a certificate is allowed;
	// anything else will cause it to be denied.
	// Redirects are not followed.
	Ask string `json:"ask,omitempty"`
}

// RateLimit specifies an interval with optional burst size.
type RateLimit struct {
	// A duration value. A certificate may be obtained 'burst'
	// times during this interval.
	Interval caddy.Duration `json:"interval,omitempty"`

	// How many times during an interval a certificate can be obtained.
	Burst int `json:"burst,omitempty"`
}

// ManagerMaker makes a certificate manager.
type ManagerMaker interface {
	NewManager(interactive bool) (certmagic.Manager, error)
}

// AutomateLoader is a no-op certificate loader module
// that is treated as a special case: it uses this app's
// automation features to load certificates for the
// list of hostnames, rather than loading certificates
// manually.
type AutomateLoader []string

// CaddyModule returns the Caddy module information.
func (AutomateLoader) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.certificates.automate",
		New: func() caddy.Module { return new(AutomateLoader) },
	}
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
