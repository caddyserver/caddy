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
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
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

	// Configures the in-memory certificate cache.
	Cache *CertCacheOptions `json:"cache,omitempty"`

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
		Logger: t.logger.Named("cache"),
	}
	if t.Automation != nil {
		cacheOpts.OCSPCheckInterval = time.Duration(t.Automation.OCSPCheckInterval)
		cacheOpts.RenewCheckInterval = time.Duration(t.Automation.RenewCheckInterval)
	}
	if t.Cache != nil {
		cacheOpts.Capacity = t.Cache.Capacity
	}
	if cacheOpts.Capacity <= 0 {
		cacheOpts.Capacity = 10000
	}
	t.certCache = certmagic.NewCache(cacheOpts)

	// certificate loaders
	val, err := ctx.LoadModule(t, "CertificatesRaw")
	if err != nil {
		return fmt.Errorf("loading certificate loader modules: %s", err)
	}
	for modName, modIface := range val.(map[string]interface{}) {
		if modName == "automate" {
			// special case; these will be loaded in later using our automation facilities,
			// which we want to avoid doing during provisioning
			if automateNames, ok := modIface.(*AutomateLoader); ok && automateNames != nil {
				t.automateNames = []string(*automateNames)
			} else {
				return fmt.Errorf("loading certificates with 'automate' requires array of strings, got: %T", modIface)
			}
			continue
		}
		t.certificateLoaders = append(t.certificateLoaders, modIface.(CertificateLoader))
	}

	// automation/management policies
	if t.Automation == nil {
		t.Automation = new(AutomationConfig)
	}
	t.Automation.defaultPublicAutomationPolicy = new(AutomationPolicy)
	err = t.Automation.defaultPublicAutomationPolicy.Provision(t)
	if err != nil {
		return fmt.Errorf("provisioning default public automation policy: %v", err)
	}
	for _, n := range t.automateNames {
		// if any names specified by the "automate" loader do not qualify for a public
		// certificate, we should initialize a default internal automation policy
		// (but we don't want to do this unnecessarily, since it may prompt for password!)
		if certmagic.SubjectQualifiesForPublicCert(n) {
			continue
		}
		t.Automation.defaultInternalAutomationPolicy = &AutomationPolicy{
			IssuersRaw: []json.RawMessage{json.RawMessage(`{"module":"internal"}`)},
		}
		err = t.Automation.defaultInternalAutomationPolicy.Provision(t)
		if err != nil {
			return fmt.Errorf("provisioning default internal automation policy: %v", err)
		}
		break
	}
	for i, ap := range t.Automation.Policies {
		err := ap.Provision(t)
		if err != nil {
			return fmt.Errorf("provisioning automation policy %d: %v", i, err)
		}
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
		Logger:  t.logger,
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
		// isn't useful and is probably a mistake; same for two
		// catch-all/default policies
		var hasDefault bool
		hostSet := make(map[string]int)
		for i, ap := range t.Automation.Policies {
			if len(ap.Subjects) == 0 {
				if hasDefault {
					return fmt.Errorf("automation policy %d is the second policy that acts as default/catch-all, but will never be used", i)
				}
				hasDefault = true
			}
			for _, h := range ap.Subjects {
				if first, ok := hostSet[h]; ok {
					return fmt.Errorf("automation policy %d: cannot apply more than one automation policy to host: %s (first match in policy %d)", i, h, first)
				}
				hostSet[h] = i
			}
		}
	}
	if t.Cache != nil {
		if t.Cache.Capacity < 0 {
			return fmt.Errorf("cache capacity must be >= 0")
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
	// use that config, rather than calling ManageAsync once for
	// every name; so first, bin names by AutomationPolicy
	policyToNames := make(map[*AutomationPolicy][]string)
	for _, name := range names {
		ap := t.getAutomationPolicyForName(name)
		policyToNames[ap] = append(policyToNames[ap], name)
	}

	// now that names are grouped by policy, we can simply make one
	// certmagic.Config for each (potentially large) group of names
	// and call ManageAsync just once for the whole batch
	for ap, names := range policyToNames {
		err := ap.magic.ManageAsync(t.ctx.Context, names)
		if err != nil {
			return fmt.Errorf("automate: manage %v: %v", names, err)
		}
	}

	return nil
}

// HandleHTTPChallenge ensures that the HTTP challenge is handled for the
// certificate named by r.Host, if it is an HTTP challenge request. It
// requires that the automation policy for r.Host has an issuer of type
// *certmagic.ACMEManager, or one that is ACME-enabled (GetACMEIssuer()).
func (t *TLS) HandleHTTPChallenge(w http.ResponseWriter, r *http.Request) bool {
	// no-op if it's not an ACME challenge request
	if !certmagic.LooksLikeHTTPChallenge(r) {
		return false
	}

	// try all the issuers until we find the one that initiated the challenge
	ap := t.getAutomationPolicyForName(r.Host)
	type acmeCapable interface{ GetACMEIssuer() *ACMEIssuer }
	for _, iss := range ap.magic.Issuers {
		if am, ok := iss.(acmeCapable); ok {
			iss := am.GetACMEIssuer()
			if certmagic.NewACMEManager(iss.magic, iss.template).HandleHTTPChallenge(w, r) {
				return true
			}
		}
	}

	// it's possible another server in this process initiated the challenge;
	// users have requested that Caddy only handle HTTP challenges it initiated,
	// so that users can proxy the others through to their backends; but we
	// might not have an automation policy for all identifiers that are trying
	// to get certificates (e.g. the admin endpoint), so we do this manual check
	if challenge, ok := certmagic.GetACMEChallenge(r.Host); ok {
		return certmagic.SolveHTTPChallenge(t.logger, w, r, challenge.Challenge)
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
	err := ap.Provision(t)
	if err != nil {
		return err
	}
	// sort new automation policies just before any other which is a superset
	// of this one; if we find an existing policy that covers every subject in
	// ap but less specifically (e.g. a catch-all policy, or one with wildcards
	// or with fewer subjects), insert ap just before it, otherwise ap would
	// never be used because the first matching policy is more general
	for i, existing := range t.Automation.Policies {
		// first see if existing is superset of ap for all names
		var otherIsSuperset bool
	outer:
		for _, thisSubj := range ap.Subjects {
			for _, otherSubj := range existing.Subjects {
				if certmagic.MatchWildcard(thisSubj, otherSubj) {
					otherIsSuperset = true
					break outer
				}
			}
		}
		// if existing AP is a superset or if it contains fewer names (i.e. is
		// more general), then new AP is more specific, so insert before it
		if otherIsSuperset || len(existing.Subjects) < len(ap.Subjects) {
			t.Automation.Policies = append(t.Automation.Policies[:i],
				append([]*AutomationPolicy{ap}, t.Automation.Policies[i:]...)...)
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

// getAutomationPolicyForName returns the first matching automation policy
// for the given subject name. If no matching policy can be found, the
// default policy is used, depending on whether the name qualifies for a
// public certificate or not.
func (t *TLS) getAutomationPolicyForName(name string) *AutomationPolicy {
	for _, ap := range t.Automation.Policies {
		if len(ap.Subjects) == 0 {
			return ap // no host filter is an automatic match
		}
		for _, h := range ap.Subjects {
			if certmagic.MatchWildcard(name, h) {
				return ap
			}
		}
	}
	if certmagic.SubjectQualifiesForPublicCert(name) || t.Automation.defaultInternalAutomationPolicy == nil {
		return t.Automation.defaultPublicAutomationPolicy
	}
	return t.Automation.defaultInternalAutomationPolicy
}

// AllMatchingCertificates returns the list of all certificates in
// the cache which could be used to satisfy the given SAN.
func (t *TLS) AllMatchingCertificates(san string) []certmagic.Certificate {
	return t.certCache.AllMatchingCertificates(san)
}

// keepStorageClean starts a goroutine that immediately cleans up all
// known storage units if it was not recently done, and then runs the
// operation at every tick from t.storageCleanTicker.
func (t *TLS) keepStorageClean() {
	t.storageCleanTicker = time.NewTicker(storageCleanInterval)
	t.storageCleanStop = make(chan struct{})
	go func() {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("[PANIC] storage cleaner: %v\n%s", err, debug.Stack())
			}
		}()
		t.cleanStorageUnits()
		for {
			select {
			case <-t.storageCleanStop:
				return
			case <-t.storageCleanTicker.C:
				t.cleanStorageUnits()
			}
		}
	}()
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
	certmagic.CleanStorage(t.ctx, t.ctx.Storage(), options)

	// then clean each storage defined in ACME automation policies
	if t.Automation != nil {
		for _, ap := range t.Automation.Policies {
			if ap.storage != nil {
				certmagic.CleanStorage(t.ctx, ap.storage, options)
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

// CertCacheOptions configures the certificate cache.
type CertCacheOptions struct {
	// Maximum number of certificates to allow in the
	// cache. If reached, certificates will be randomly
	// evicted to make room for new ones. Default: 0
	// (no limit).
	Capacity int `json:"capacity,omitempty"`
}

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
	_ caddy.Validator    = (*TLS)(nil)
	_ caddy.CleanerUpper = (*TLS)(nil)
)

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
	oldCANames := make([]string, 0, len(oldAcmeCas))
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
