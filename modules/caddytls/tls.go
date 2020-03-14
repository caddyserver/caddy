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
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
	"github.com/go-acme/lego/v3/challenge"
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
		GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
			return t.getConfigForName(cert.Names[0]), nil
		},
	}
	if t.Automation != nil {
		cacheOpts.OCSPCheckInterval = time.Duration(t.Automation.OCSPCheckInterval)
		cacheOpts.RenewCheckInterval = time.Duration(t.Automation.RenewCheckInterval)
	}
	t.certCache = certmagic.NewCache(cacheOpts)

	// automation/management policies
	if t.Automation == nil {
		t.Automation = new(AutomationConfig)
	}
	t.Automation.defaultAutomationPolicy = new(AutomationPolicy)
	err := t.Automation.defaultAutomationPolicy.provision(t)
	if err != nil {
		return fmt.Errorf("provisioning default automation policy: %v", err)
	}
	for i, ap := range t.Automation.Policies {
		err := ap.provision(t)
		if err != nil {
			return fmt.Errorf("provisioning automation policy %d: %v", i, err)
		}
	}

	// certificate loaders
	val, err := ctx.LoadModule(t, "CertificatesRaw")
	if err != nil {
		return fmt.Errorf("loading certificate loader modules: %s", err)
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

	// TODO: TEMPORARY UNTIL RELEASE CANDIDATES:
	// MIGRATE MANAGED CERTIFICATE ASSETS TO NEW PATH
	err = t.moveCertificates()
	if err != nil {
		t.logger.Error("migrating certificates", zap.Error(err))
	}
	// END TODO: TEMPORARY.

	return nil
}

// Validate validates t's configuration.
func (t *TLS) Validate() error {
	if t.Automation != nil {
		// ensure that host aren't repeated; since only the first
		// automation policy is used, repeating a host in the lists
		// isn't useful and is probably a mistake
		hostSet := make(map[string]int)
		for i, ap := range t.Automation.Policies {
			for _, h := range ap.Hosts {
				if first, ok := hostSet[h]; ok {
					return fmt.Errorf("automation policy %d: cannot apply more than one automation policy to host: %s (first match in policy %d)", i, h, first)
				}
				hostSet[h] = i
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
	// for a large number of names, we can be more memory-efficient
	// by making only one certmagic.Config for all the names that
	// use that config, rather than calling ManageSync/ManageAsync
	// once for every name; so first, bin names by AutomationPolicy
	policyToNames := make(map[*AutomationPolicy][]string)
	for _, name := range names {
		ap := t.getAutomationPolicyForName(name)
		policyToNames[ap] = append(policyToNames[ap], name)
	}

	// now that names are grouped by policy, we can simply make one
	// certmagic.Config for each (potentially large) group of names
	// and call ManageSync/ManageAsync just once for the whole batch
	for ap, names := range policyToNames {
		var err error
		if ap.ManageSync {
			err = ap.magic.ManageSync(names)
		} else {
			err = ap.magic.ManageAsync(t.ctx.Context, names)
		}
		if err != nil {
			return fmt.Errorf("automate: manage %v: %v", names, err)
		}
	}

	return nil
}

// HandleHTTPChallenge ensures that the HTTP challenge is handled for the
// certificate named by r.Host, if it is an HTTP challenge request. It
// requires that the automation policy for r.Host has an issue of type
// *certmagic.ACMEManager.
func (t *TLS) HandleHTTPChallenge(w http.ResponseWriter, r *http.Request) bool {
	if !certmagic.LooksLikeHTTPChallenge(r) {
		return false
	}
	ap := t.getAutomationPolicyForName(r.Host)
	if ap.magic.Issuer == nil {
		return false
	}
	if am, ok := ap.magic.Issuer.(*ACMEIssuer); ok {
		return certmagic.NewACMEManager(am.magic, am.template).HandleHTTPChallenge(w, r)
	}
	return false
}

// AddAutomationPolicy provisions and adds ap to the list of the app's
// automation policies. If an existing automation policy exists that has
// fewer hosts in its list than ap does, ap will be inserted before that
// other policy (this helps ensure that ap will be prioritized/chosen
// over, say, a catch-all policy).
func (t *TLS) AddAutomationPolicy(ap *AutomationPolicy) error {
	if t.Automation == nil {
		t.Automation = new(AutomationConfig)
	}
	err := ap.provision(t)
	if err != nil {
		return err
	}
	for i, other := range t.Automation.Policies {
		// if a catch-all policy (or really, any policy with
		// fewer names) exists, prioritize this new policy
		if len(other.Hosts) < len(ap.Hosts) {
			t.Automation.Policies = append(t.Automation.Policies[:i],
				append([]*AutomationPolicy{ap}, t.Automation.Policies[i+1:]...)...)
			return nil
		}
	}
	// otherwise just append the new one
	t.Automation.Policies = append(t.Automation.Policies, ap)
	return nil
}

func (t *TLS) getConfigForName(name string) *certmagic.Config {
	ap := t.getAutomationPolicyForName(name)
	return ap.magic
}

func (t *TLS) getAutomationPolicyForName(name string) *AutomationPolicy {
	for _, ap := range t.Automation.Policies {
		if len(ap.Hosts) == 0 {
			return ap // no host filter is an automatic match
		}
		for _, h := range ap.Hosts {
			if h == name {
				return ap
			}
		}
	}
	return t.Automation.defaultAutomationPolicy
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
			if ap.storage != nil {
				certmagic.CleanStorage(ap.storage, options)
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
	Policies []*AutomationPolicy `json:"policies,omitempty"`

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
	// certificates for expiration. This setting changes how
	// frequently the scan for expiring certificates is
	// performed. If your certificate lifetimes are very
	// short (less than ~24 hours), you should set this to
	// a low value.
	RenewCheckInterval caddy.Duration `json:"renew_interval,omitempty"`

	defaultAutomationPolicy *AutomationPolicy
}

// AutomationPolicy designates the policy for automating the
// management (obtaining, renewal, and revocation) of managed
// TLS certificates.
//
// An AutomationPolicy value is not valid until it has been
// provisioned; use the `AddAutomationPolicy()` method on the
// TLS app to properly provision a new policy.
type AutomationPolicy struct {
	// Which hostnames this policy applies to.
	Hosts []string `json:"hosts,omitempty"`

	// The module that will issue certificates. Default: acme
	IssuerRaw json.RawMessage `json:"issuer,omitempty" caddy:"namespace=tls.issuance inline_key=module"`

	// If true, certificates will be requested with MustStaple. Not all
	// CAs support this, and there are potentially serious consequences
	// of enabling this feature without proper threat modeling.
	MustStaple bool `json:"must_staple,omitempty"`

	// How long before a certificate's expiration to try renewing it,
	// as a function of its total lifetime. As a general and conservative
	// rule, it is a good idea to renew a certificate when it has about
	// 1/3 of its total lifetime remaining. This utilizes the majority
	// of the certificate's lifetime while still saving time to
	// troubleshoot problems. However, for extremely short-lived certs,
	// you may wish to increase the ratio to ~1/2.
	RenewalWindowRatio float64 `json:"renewal_window_ratio,omitempty"`

	// The type of key to generate for certificates.
	// Supported values: `ed25519`, `p256`, `p384`, `rsa2048`, `rsa4096`.
	KeyType string `json:"key_type,omitempty"`

	// Optionally configure a separate storage module associated with this
	// manager, instead of using Caddy's global/default-configured storage.
	StorageRaw json.RawMessage `json:"storage,omitempty" caddy:"namespace=caddy.storage inline_key=module"`

	// If true, certificates will be managed "on demand", that is, during
	// TLS handshakes or when needed, as opposed to at startup or config
	// load.
	OnDemand bool `json:"on_demand,omitempty"`

	// If true, certificate management will be conducted
	// in the foreground; this will block config reloads
	// and return errors if there were problems with
	// obtaining or renewing certificates. This is often
	// not desirable, especially when serving sites out
	// of your control. Default: false
	// TODO: is this really necessary per-policy? why not a global setting...
	ManageSync bool `json:"manage_sync,omitempty"`

	Issuer certmagic.Issuer `json:"-"`

	magic   *certmagic.Config
	storage certmagic.Storage
}

// provision converts ap into a CertMagic config.
func (ap *AutomationPolicy) provision(tlsApp *TLS) error {
	// policy-specific storage implementation
	if ap.StorageRaw != nil {
		val, err := tlsApp.ctx.LoadModule(ap, "StorageRaw")
		if err != nil {
			return fmt.Errorf("loading TLS storage module: %v", err)
		}
		cmStorage, err := val.(caddy.StorageConverter).CertMagicStorage()
		if err != nil {
			return fmt.Errorf("creating TLS storage configuration: %v", err)
		}
		ap.storage = cmStorage
	}

	var ond *certmagic.OnDemandConfig
	if ap.OnDemand {
		var onDemand *OnDemandConfig
		if tlsApp.Automation != nil {
			onDemand = tlsApp.Automation.OnDemand
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

	keySource := certmagic.StandardKeyGenerator{
		KeyType: supportedCertKeyTypes[ap.KeyType],
	}

	storage := ap.storage
	if storage == nil {
		storage = tlsApp.ctx.Storage()
	}

	template := certmagic.Config{
		MustStaple:         ap.MustStaple,
		RenewalWindowRatio: ap.RenewalWindowRatio,
		KeySource:          keySource,
		OnDemand:           ond,
		Storage:            storage,
	}
	ap.magic = certmagic.New(tlsApp.certCache, template)

	if ap.IssuerRaw != nil {
		val, err := tlsApp.ctx.LoadModule(ap, "IssuerRaw")
		if err != nil {
			return fmt.Errorf("loading TLS automation management module: %s", err)
		}
		ap.Issuer = val.(certmagic.Issuer)
	}

	// sometimes issuers may need the parent certmagic.Config in
	// order to function properly (for example, ACMEIssuer needs
	// access to the correct storage and cache so it can solve
	// ACME challenges -- it's an annoying, inelegant circular
	// dependency that I don't know how to resolve nicely!)
	if configger, ok := ap.Issuer.(ConfigSetter); ok {
		configger.SetConfig(ap.magic)
	}

	ap.magic.Issuer = ap.Issuer
	if rev, ok := ap.Issuer.(certmagic.Revoker); ok {
		ap.magic.Revoker = rev
	}

	return nil
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

// ConfigSetter is implemented by certmagic.Issuers that
// need access to a parent certmagic.Config as part of
// their provisioning phase. For example, the ACMEIssuer
// requires a config so it can access storage and the
// cache to solve ACME challenges.
type ConfigSetter interface {
	SetConfig(cfg *certmagic.Config)
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

// TODO: This is temporary until the release candidates
// (beta 16 changed the storage path for certificates),
// after which this function can be deleted
func (t *TLS) moveCertificates() error {
	logger := t.logger.Named("automigrate")

	baseDir := caddy.AppDataDir()

	// if custom storage path was defined, use that instead
	if fs, ok := t.ctx.Storage().(*certmagic.FileStorage); ok && fs.Path != "" {
		baseDir = fs.Path
	}

	oldAcmeDir := filepath.Join(baseDir, "acme")
	oldAcmeCas, err := ioutil.ReadDir(oldAcmeDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("listing used ACME CAs: %v", err)
	}

	// get list of used CAs
	var oldCANames []string
	for _, fi := range oldAcmeCas {
		if !fi.IsDir() {
			continue
		}
		oldCANames = append(oldCANames, fi.Name())
	}

	for _, oldCA := range oldCANames {
		// make new destination path
		newCAName := oldCA
		if strings.Contains(oldCA, "api.letsencrypt.org") &&
			!strings.HasSuffix(oldCA, "-directory") {
			newCAName += "-directory"
		}
		newBaseDir := filepath.Join(baseDir, "certificates", newCAName)
		err := os.MkdirAll(newBaseDir, 0700)
		if err != nil {
			return fmt.Errorf("making new certs directory: %v", err)
		}

		// list sites in old path
		oldAcmeSitesDir := filepath.Join(oldAcmeDir, oldCA, "sites")
		oldAcmeSites, err := ioutil.ReadDir(oldAcmeSitesDir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("listing sites: %v", err)
		}

		if len(oldAcmeSites) > 0 {
			logger.Warn("certificate storage path has changed; attempting one-time auto-migration",
				zap.String("old_folder", oldAcmeSitesDir),
				zap.String("new_folder", newBaseDir),
				zap.String("details", "https://github.com/caddyserver/caddy/issues/2955"))
		}

		// for each site, move its folder and re-encode its metadata
		for _, siteInfo := range oldAcmeSites {
			if !siteInfo.IsDir() {
				continue
			}

			// move the folder
			oldPath := filepath.Join(oldAcmeSitesDir, siteInfo.Name())
			newPath := filepath.Join(newBaseDir, siteInfo.Name())
			logger.Info("moving certificate assets",
				zap.String("ca", oldCA),
				zap.String("site", siteInfo.Name()),
				zap.String("destination", newPath))
			err = os.Rename(oldPath, newPath)
			if err != nil {
				logger.Error("failed moving site to new path; skipping",
					zap.String("old_path", oldPath),
					zap.String("new_path", newPath),
					zap.Error(err))
				continue
			}

			// re-encode metadata file
			metaFilePath := filepath.Join(newPath, siteInfo.Name()+".json")
			metaContents, err := ioutil.ReadFile(metaFilePath)
			if err != nil {
				logger.Error("could not read metadata file",
					zap.String("filename", metaFilePath),
					zap.Error(err))
				continue
			}
			if len(metaContents) == 0 {
				continue
			}
			cr := certmagic.CertificateResource{
				SANs:       []string{siteInfo.Name()},
				IssuerData: json.RawMessage(metaContents),
			}
			newMeta, err := json.MarshalIndent(cr, "", "\t")
			if err != nil {
				logger.Error("encoding new metadata file", zap.Error(err))
				continue
			}
			err = ioutil.WriteFile(metaFilePath, newMeta, 0600)
			if err != nil {
				logger.Error("writing new metadata file", zap.Error(err))
				continue
			}
		}

		// delete now-empty old sites dir (OK if fails)
		os.Remove(oldAcmeSitesDir)
	}

	return nil
}

// Interface guards
var (
	_ caddy.Provisioner = (*TLS)(nil)
	_ caddy.Validator   = (*TLS)(nil)
	_ caddy.App         = (*TLS)(nil)
)
