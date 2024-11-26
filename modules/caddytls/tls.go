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
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"runtime/debug"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyevents"
)

func init() {
	caddy.RegisterModule(TLS{})
	caddy.RegisterModule(AutomateLoader{})
}

var (
	certCache   *certmagic.Cache
	certCacheMu sync.RWMutex
)

// TLS provides TLS facilities including certificate
// loading and management, client auth, and more.
type TLS struct {
	// Certificates to load into memory for quick recall during
	// TLS handshakes. Each key is the name of a certificate
	// loader module.
	//
	// The "automate" certificate loader module can be used to
	// specify a list of subjects that need certificates to be
	// managed automatically. The first matching automation
	// policy will be applied to manage the certificate(s).
	//
	// All loaded certificates get pooled
	// into the same cache and may be used to complete TLS
	// handshakes for the relevant server names (SNI).
	// Certificates loaded manually (anything other than
	// "automate") are not automatically managed and will
	// have to be refreshed manually before they expire.
	CertificatesRaw caddy.ModuleMap `json:"certificates,omitempty" caddy:"namespace=tls.certificates"`

	// Configures certificate automation.
	Automation *AutomationConfig `json:"automation,omitempty"`

	// Configures session ticket ephemeral keys (STEKs).
	SessionTickets *SessionTicketService `json:"session_tickets,omitempty"`

	// Configures the in-memory certificate cache.
	Cache *CertCacheOptions `json:"cache,omitempty"`

	// Disables OCSP stapling for manually-managed certificates only.
	// To configure OCSP stapling for automated certificates, use an
	// automation policy instead.
	//
	// Disabling OCSP stapling puts clients at greater risk, reduces their
	// privacy, and usually lowers client performance. It is NOT recommended
	// to disable this unless you are able to justify the costs.
	// EXPERIMENTAL. Subject to change.
	DisableOCSPStapling bool `json:"disable_ocsp_stapling,omitempty"`

	// Disables checks in certmagic that the configured storage is ready
	// and able to handle writing new content to it. These checks are
	// intended to prevent information loss (newly issued certificates), but
	// can be expensive on the storage.
	//
	// Disabling these checks should only be done when the storage
	// can be trusted to have enough capacity and no other problems.
	// EXPERIMENTAL. Subject to change.
	DisableStorageCheck bool `json:"disable_storage_check,omitempty"`

	// Disables the automatic cleanup of the storage backend.
	// This is useful when TLS is not being used to store certificates
	// and the user wants run their server in a read-only mode.
	//
	// Storage cleaning creates two files: instance.uuid and last_clean.json.
	// The instance.uuid file is used to identify the instance of Caddy
	// in a cluster. The last_clean.json file is used to store the last
	// time the storage was cleaned.
	// EXPERIMENTAL. Subject to change.
	DisableStorageClean bool `json:"disable_storage_clean,omitempty"`

	certificateLoaders []CertificateLoader
	automateNames      []string
	ctx                caddy.Context
	storageCleanTicker *time.Ticker
	storageCleanStop   chan struct{}
	logger             *zap.Logger
	events             *caddyevents.App

	// set of subjects with managed certificates,
	// and hashes of manually-loaded certificates
	// (managing's value is an optional issuer key, for distinction)
	managing, loaded map[string]string
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
	eventsAppIface, err := ctx.App("events")
	if err != nil {
		return fmt.Errorf("getting events app: %v", err)
	}
	t.events = eventsAppIface.(*caddyevents.App)
	t.ctx = ctx
	t.logger = ctx.Logger()
	repl := caddy.NewReplacer()
	t.managing, t.loaded = make(map[string]string), make(map[string]string)

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

	certCacheMu.Lock()
	if certCache == nil {
		certCache = certmagic.NewCache(cacheOpts)
	} else {
		certCache.SetOptions(cacheOpts)
	}
	certCacheMu.Unlock()

	// certificate loaders
	val, err := ctx.LoadModule(t, "CertificatesRaw")
	if err != nil {
		return fmt.Errorf("loading certificate loader modules: %s", err)
	}
	for modName, modIface := range val.(map[string]any) {
		if modName == "automate" {
			// special case; these will be loaded in later using our automation facilities,
			// which we want to avoid doing during provisioning
			if automateNames, ok := modIface.(*AutomateLoader); ok && automateNames != nil {
				repl := caddy.NewReplacer()
				subjects := make([]string, len(*automateNames))
				for i, sub := range *automateNames {
					subjects[i] = repl.ReplaceAll(sub, "")
				}
				t.automateNames = subjects
			} else {
				return fmt.Errorf("loading certificates with 'automate' requires array of strings, got: %T", modIface)
			}
			continue
		}
		t.certificateLoaders = append(t.certificateLoaders, modIface.(CertificateLoader))
	}

	// on-demand permission module
	if t.Automation != nil && t.Automation.OnDemand != nil && t.Automation.OnDemand.PermissionRaw != nil {
		if t.Automation.OnDemand.Ask != "" {
			return fmt.Errorf("on-demand TLS config conflict: both 'ask' endpoint and a 'permission' module are specified; 'ask' is deprecated, so use only the permission module")
		}
		val, err := ctx.LoadModule(t.Automation.OnDemand, "PermissionRaw")
		if err != nil {
			return fmt.Errorf("loading on-demand TLS permission module: %v", err)
		}
		t.Automation.OnDemand.permission = val.(OnDemandPermission)
	}

	// run replacer on ask URL (for environment variables) -- return errors to prevent surprises (#5036)
	if t.Automation != nil && t.Automation.OnDemand != nil && t.Automation.OnDemand.Ask != "" {
		t.Automation.OnDemand.Ask, err = repl.ReplaceOrErr(t.Automation.OnDemand.Ask, true, true)
		if err != nil {
			return fmt.Errorf("preparing 'ask' endpoint: %v", err)
		}
		perm := PermissionByHTTP{
			Endpoint: t.Automation.OnDemand.Ask,
		}
		if err := perm.Provision(ctx); err != nil {
			return fmt.Errorf("provisioning 'ask' module: %v", err)
		}
		t.Automation.OnDemand.permission = perm
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

	// load manual/static (unmanaged) certificates - we do this in
	// provision so that other apps (such as http) can know which
	// certificates have been manually loaded, and also so that
	// commands like validate can be a better test
	certCacheMu.RLock()
	magic := certmagic.New(certCache, certmagic.Config{
		Storage: ctx.Storage(),
		Logger:  t.logger,
		OnEvent: t.onEvent,
		OCSP: certmagic.OCSPConfig{
			DisableStapling: t.DisableOCSPStapling,
		},
		DisableStorageCheck: t.DisableStorageCheck,
	})
	certCacheMu.RUnlock()
	for _, loader := range t.certificateLoaders {
		certs, err := loader.LoadCertificates()
		if err != nil {
			return fmt.Errorf("loading certificates: %v", err)
		}
		for _, cert := range certs {
			hash, err := magic.CacheUnmanagedTLSCertificate(ctx, cert.Certificate, cert.Tags)
			if err != nil {
				return fmt.Errorf("caching unmanaged certificate: %v", err)
			}
			t.loaded[hash] = ""
		}
	}

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
			if len(ap.subjects) == 0 {
				if hasDefault {
					return fmt.Errorf("automation policy %d is the second policy that acts as default/catch-all, but will never be used", i)
				}
				hasDefault = true
			}
			for _, h := range ap.subjects {
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
	// warn if on-demand TLS is enabled but no restrictions are in place
	if t.Automation.OnDemand == nil || (t.Automation.OnDemand.Ask == "" && t.Automation.OnDemand.permission == nil) {
		for _, ap := range t.Automation.Policies {
			if ap.OnDemand && ap.isWildcardOrDefault() {
				if c := t.logger.Check(zapcore.WarnLevel, "YOUR SERVER MAY BE VULNERABLE TO ABUSE: on-demand TLS is enabled, but no protections are in place"); c != nil {
					c.Write(zap.String("docs", "https://caddyserver.com/docs/automatic-https#on-demand-tls"))
				}
				break
			}
		}
	}

	// now that we are running, and all manual certificates have
	// been loaded, time to load the automated/managed certificates
	err := t.Manage(t.automateNames)
	if err != nil {
		return fmt.Errorf("automate: managing %v: %v", t.automateNames, err)
	}

	if !t.DisableStorageClean {
		// start the storage cleaner goroutine and ticker,
		// which cleans out expired certificates and more
		t.keepStorageClean()
	}

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
	// stop the session ticket rotation goroutine
	if t.SessionTickets != nil {
		t.SessionTickets.stop()
	}

	// if a new TLS app was loaded, remove certificates from the cache that are no longer
	// being managed or loaded by the new config; if there is no more TLS app running,
	// then stop cert maintenance and let the cert cache be GC'ed
	if nextTLS, err := caddy.ActiveContext().AppIfConfigured("tls"); err == nil && nextTLS != nil {
		nextTLSApp := nextTLS.(*TLS)

		// compute which certificates were managed or loaded into the cert cache by this
		// app instance (which is being stopped) that are not managed or loaded by the
		// new app instance (which just started), and remove them from the cache
		var noLongerManaged []certmagic.SubjectIssuer
		var reManage, noLongerLoaded []string
		for subj, currentIssuerKey := range t.managing {
			// It's a bit nuanced: managed certs can sometimes be different enough that we have to
			// swap them out for a different one, even if they are for the same subject/domain.
			// We consider "private" certs (internal CA/locally-trusted/etc) to be significantly
			// distinct from "public" certs (production CAs/globally-trusted/etc) because of the
			// implications when it comes to actual deployments: switching between an internal CA
			// and a production CA, for example, is quite significant. Switching from one public CA
			// to another, however, is not, and for our purposes we consider those to be the same.
			// Anyway, if the next TLS app does not manage a cert for this name at all, definitely
			// remove it from the cache. But if it does, and it's not the same kind of issuer/CA
			// as we have, also remove it, so that it can swap it out for the right one.
			if nextIssuerKey, ok := nextTLSApp.managing[subj]; !ok || nextIssuerKey != currentIssuerKey {
				// next app is not managing a cert for this domain at all or is using a different issuer, so remove it
				noLongerManaged = append(noLongerManaged, certmagic.SubjectIssuer{Subject: subj, IssuerKey: currentIssuerKey})

				// then, if the next app is managing a cert for this name, but with a different issuer, re-manage it
				if ok && nextIssuerKey != currentIssuerKey {
					reManage = append(reManage, subj)
				}
			}
		}
		for hash := range t.loaded {
			if _, ok := nextTLSApp.loaded[hash]; !ok {
				noLongerLoaded = append(noLongerLoaded, hash)
			}
		}

		// remove the certs
		certCacheMu.RLock()
		certCache.RemoveManaged(noLongerManaged)
		certCache.Remove(noLongerLoaded)
		certCacheMu.RUnlock()

		// give the new TLS app a "kick" to manage certs that it is configured for
		// with its own configuration instead of the one we just evicted
		if err := nextTLSApp.Manage(reManage); err != nil {
			if c := t.logger.Check(zapcore.ErrorLevel, "re-managing unloaded certificates with new config"); c != nil {
				c.Write(
					zap.Strings("subjects", reManage),
					zap.Error(err),
				)
			}
		}
	} else {
		// no more TLS app running, so delete in-memory cert cache
		certCache.Stop()
		certCacheMu.Lock()
		certCache = nil
		certCacheMu.Unlock()
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
			const maxNamesToDisplay = 100
			if len(names) > maxNamesToDisplay {
				names = append(names[:maxNamesToDisplay], fmt.Sprintf("(%d more...)", len(names)-maxNamesToDisplay))
			}
			return fmt.Errorf("automate: manage %v: %v", names, err)
		}
		for _, name := range names {
			// certs that are issued solely by our internal issuer are a little bit of
			// a special case: if you have an initial config that manages example.com
			// using internal CA, then after testing it you switch to a production CA,
			// you wouldn't want to keep using the same self-signed cert, obviously;
			// so we differentiate these by associating the subject with its issuer key;
			// we do this because CertMagic has no notion of "InternalIssuer" like we
			// do, so we have to do this logic ourselves
			var issuerKey string
			if len(ap.Issuers) == 1 {
				if intIss, ok := ap.Issuers[0].(*InternalIssuer); ok && intIss != nil {
					issuerKey = intIss.IssuerKey()
				}
			}
			t.managing[name] = issuerKey
		}
	}

	return nil
}

// HandleHTTPChallenge ensures that the ACME HTTP challenge or ZeroSSL HTTP
// validation request is handled for the certificate named by r.Host, if it
// is an HTTP challenge request. It requires that the automation policy for
// r.Host has an issuer that implements GetACMEIssuer() or is a *ZeroSSLIssuer.
func (t *TLS) HandleHTTPChallenge(w http.ResponseWriter, r *http.Request) bool {
	acmeChallenge := certmagic.LooksLikeHTTPChallenge(r)
	zerosslValidation := certmagic.LooksLikeZeroSSLHTTPValidation(r)

	// no-op if it's not an ACME challenge request
	if !acmeChallenge && !zerosslValidation {
		return false
	}

	// try all the issuers until we find the one that initiated the challenge
	ap := t.getAutomationPolicyForName(r.Host)

	if acmeChallenge {
		type acmeCapable interface{ GetACMEIssuer() *ACMEIssuer }

		for _, iss := range ap.magic.Issuers {
			if acmeIssuer, ok := iss.(acmeCapable); ok {
				if acmeIssuer.GetACMEIssuer().issuer.HandleHTTPChallenge(w, r) {
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
	} else if zerosslValidation {
		for _, iss := range ap.magic.Issuers {
			if ziss, ok := iss.(*ZeroSSLIssuer); ok {
				if ziss.issuer.HandleZeroSSLHTTPValidation(w, r) {
					return true
				}
			}
		}
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
		for _, thisSubj := range ap.subjects {
			for _, otherSubj := range existing.subjects {
				if certmagic.MatchWildcard(thisSubj, otherSubj) {
					otherIsSuperset = true
					break outer
				}
			}
		}
		// if existing AP is a superset or if it contains fewer names (i.e. is
		// more general), then new AP is more specific, so insert before it
		if otherIsSuperset || len(existing.SubjectsRaw) < len(ap.SubjectsRaw) {
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
		if len(ap.subjects) == 0 {
			return ap // no host filter is an automatic match
		}
		for _, h := range ap.subjects {
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
func AllMatchingCertificates(san string) []certmagic.Certificate {
	return certCache.AllMatchingCertificates(san)
}

func (t *TLS) HasCertificateForSubject(subject string) bool {
	certCacheMu.RLock()
	allMatchingCerts := certCache.AllMatchingCertificates(subject)
	certCacheMu.RUnlock()
	for _, cert := range allMatchingCerts {
		// check if the cert is manually loaded by this config
		if _, ok := t.loaded[cert.Hash()]; ok {
			return true
		}
		// check if the cert is automatically managed by this config
		for _, name := range cert.Names {
			if _, ok := t.managing[name]; ok {
				return true
			}
		}
	}
	return false
}

// keepStorageClean starts a goroutine that immediately cleans up all
// known storage units if it was not recently done, and then runs the
// operation at every tick from t.storageCleanTicker.
func (t *TLS) keepStorageClean() {
	t.storageCleanTicker = time.NewTicker(t.storageCleanInterval())
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

	// TODO: This check might not be needed anymore now that CertMagic syncs
	// and throttles storage cleaning globally across the cluster.
	// The original comment below might be outdated:
	//
	// If storage was cleaned recently, don't do it again for now. Although the ticker
	// calling this function drops missed ticks for us, config reloads discard the old
	// ticker and replace it with a new one, possibly invoking a cleaning to happen again
	// too soon. (We divide the interval by 2 because the actual cleaning takes non-zero
	// time, and we don't want to skip cleanings if we don't have to; whereas if a cleaning
	// took most of the interval, we'd probably want to skip the next one so we aren't
	// constantly cleaning. This allows cleanings to take up to half the interval's
	// duration before we decide to skip the next one.)
	if !storageClean.IsZero() && time.Since(storageClean) < t.storageCleanInterval()/2 {
		return
	}

	id, err := caddy.InstanceID()
	if err != nil {
		if c := t.logger.Check(zapcore.WarnLevel, "unable to get instance ID; storage clean stamps will be incomplete"); c != nil {
			c.Write(zap.Error(err))
		}
	}
	options := certmagic.CleanStorageOptions{
		Logger:                 t.logger,
		InstanceID:             id.String(),
		Interval:               t.storageCleanInterval(),
		OCSPStaples:            true,
		ExpiredCerts:           true,
		ExpiredCertGracePeriod: 24 * time.Hour * 14,
	}

	// start with the default/global storage
	err = certmagic.CleanStorage(t.ctx, t.ctx.Storage(), options)
	if err != nil {
		// probably don't want to return early, since we should still
		// see if any other storages can get cleaned up
		if c := t.logger.Check(zapcore.ErrorLevel, "could not clean default/global storage"); c != nil {
			c.Write(zap.Error(err))
		}
	}

	// then clean each storage defined in ACME automation policies
	if t.Automation != nil {
		for _, ap := range t.Automation.Policies {
			if ap.storage == nil {
				continue
			}
			if err := certmagic.CleanStorage(t.ctx, ap.storage, options); err != nil {
				if c := t.logger.Check(zapcore.ErrorLevel, "could not clean storage configured in automation policy"); c != nil {
					c.Write(zap.Error(err))
				}
			}
		}
	}

	// remember last time storage was finished cleaning
	storageClean = time.Now()

	t.logger.Info("finished cleaning storage units")
}

func (t *TLS) storageCleanInterval() time.Duration {
	if t.Automation != nil && t.Automation.StorageCleanInterval > 0 {
		return time.Duration(t.Automation.StorageCleanInterval)
	}
	return defaultStorageCleanInterval
}

// onEvent translates CertMagic events into Caddy events then dispatches them.
func (t *TLS) onEvent(ctx context.Context, eventName string, data map[string]any) error {
	evt := t.events.Emit(t.ctx, eventName, data)
	return evt.Aborted
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

// AutomateLoader will automatically manage certificates for the names in the
// list, including obtaining and renewing certificates. Automated certificates
// are managed according to their matching automation policy, configured
// elsewhere in this app.
//
// Technically, this is a no-op certificate loader module that is treated as
// a special case: it uses this app's automation features to load certificates
// for the list of hostnames, rather than loading certificates manually. But
// the end result is the same: certificates for these subject names will be
// loaded into the in-memory cache and may then be used.
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
	// evicted to make room for new ones. Default: 10,000
	Capacity int `json:"capacity,omitempty"`
}

// Variables related to storage cleaning.
var (
	defaultStorageCleanInterval = 24 * time.Hour

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
