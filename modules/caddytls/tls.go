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
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/libdns"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/internal"
	"github.com/caddyserver/caddy/v2/modules/caddyevents"
)

func init() {
	caddy.RegisterModule(TLS{})
	caddy.RegisterModule(AutomateLoader{})
}

// The certificate cache of the currently-committed config. A TLS app
// instance provisions the cache it will use into its own cache field and
// only publishes it here from Start, once provisioning has succeeded; the
// outgoing app stops the cache it owned from Cleanup, after the new config
// is committed. Provision therefore neither publishes nor destroys a
// cache, so a config that fails to provision or start leaves the
// committed config's cache untouched and still maintained.
var (
	certCache   *certmagic.Cache
	certCacheMu sync.RWMutex

	// the TLS app owning the published cache; the cache's
	// GetConfigForCert callback dereferences this so that reusing the
	// cache across config reloads does not require replacing its
	// options just to update the callback
	certCacheApp *TLS

	// the options the published cache was created with; CacheOptions are
	// immutable once a cache exists (its maintenance tickers are created
	// at startup), so when a reload changes them the cache is replaced,
	// never mutated
	certCacheOpts certmagic.CacheOptions
)

// normalizeCacheOptions applies the same defaulting certmagic.NewCache
// applies to the fields that determine whether a cache can be reused, so
// that an explicitly-configured interval compares equal to an unset one
// that certmagic would default to the same value. Without this, setting
// e.g. renew_interval to 10m — certmagic's own default — would differ from
// leaving it unset and force a needless cache replacement.
func normalizeCacheOptions(opts certmagic.CacheOptions) certmagic.CacheOptions {
	if opts.OCSPCheckInterval <= 0 {
		opts.OCSPCheckInterval = certmagic.DefaultOCSPCheckInterval
	}
	if opts.RenewCheckInterval <= 0 {
		opts.RenewCheckInterval = certmagic.DefaultRenewCheckInterval
	}
	if opts.Capacity < 0 {
		opts.Capacity = 0
	}
	return opts
}

// cacheReusable reports whether a cache created with have can serve a
// config wanting want. Only the fields fixed at cache creation matter;
// both must already be normalized.
func cacheReusable(have, want certmagic.CacheOptions) bool {
	return have.Capacity == want.Capacity &&
		have.OCSPCheckInterval == want.OCSPCheckInterval &&
		have.RenewCheckInterval == want.RenewCheckInterval
}

// provisionCertCache sets t.cache to the cache t should use. The published
// cache is reused when its options permit it; otherwise a new cache is
// created for t alone. CacheOptions are immutable once a cache is created:
// the maintenance goroutine's tickers are built from the options at
// startup, so mutating options on a live cache both races with maintenance
// reading them and silently never applies new intervals to the running
// tickers. A cache is therefore replaced, never mutated.
//
// This neither publishes the result nor stops the cache it replaces — the
// cache stays private to t until Start publishes it, so handshakes and
// maintenance on the committed config keep using the published cache until
// the new config is committed.
//
// t.cache and t.cacheOpts are written under certCacheMu because a cache's
// GetConfigForCert callback reads them (see appForCache) from the
// maintenance goroutine.
func (t *TLS) provisionCertCache(cacheOpts certmagic.CacheOptions) {
	certCacheMu.Lock()
	reusable := certCache != nil && cacheReusable(certCacheOpts, cacheOpts)
	if reusable {
		t.cache, t.cacheOpts = certCache, cacheOpts
	}
	certCacheMu.Unlock()
	if reusable {
		return
	}
	// created outside the lock: NewCache starts a maintenance goroutine
	// whose callback takes certCacheMu. The new cache is empty until
	// provisioning loads into it, so that callback cannot run before the
	// assignment below publishes the cache to t.
	fresh := certmagic.NewCache(cacheOpts)
	certCacheMu.Lock()
	t.cache, t.cacheOpts = fresh, cacheOpts
	certCacheMu.Unlock()
}

// appForCache returns the TLS app whose configuration governs certificates
// in t.cache. A cache's GetConfigForCert callback is fixed when the cache
// is created, so a cache reused across reloads holds the callback created
// by the app that first built it; while that cache is the published one,
// maintenance must consult whichever app currently owns it rather than its
// original creator. A cache that is not (or not yet) published is only
// populated by the app that created it, so t is the right answer there —
// which is also what this returns once t publishes its own cache.
func (t *TLS) appForCache() *TLS {
	certCacheMu.RLock()
	defer certCacheMu.RUnlock()
	if certCacheApp != nil && certCache == t.cache {
		return certCacheApp
	}
	return t
}

// publishCertCache makes t's cache the one the committed config serves
// from. Called from Start, i.e. only after provisioning succeeded.
func (t *TLS) publishCertCache() {
	certCacheMu.Lock()
	defer certCacheMu.Unlock()
	certCache = t.cache
	certCacheOpts = t.cacheOpts
	certCacheApp = t
}

// TLS provides TLS facilities including certificate
// loading and management, client auth, and more.
type TLS struct {
	// Certificates to load into memory for quick recall during
	// TLS handshakes. Each key is the name of a certificate
	// loader module.
	//
	// The "automate" certificate loader module can be used to
	// specify a list of subjects that need certificates to be
	// managed automatically, including subdomains that may
	// already be covered by a managed wildcard certificate.
	// The first matching automation policy will be used
	// to manage automated certificate(s).
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
	//
	// EXPERIMENTAL. Subject to change.
	DisableOCSPStapling bool `json:"disable_ocsp_stapling,omitempty"`

	// Disables checks in certmagic that the configured storage is ready
	// and able to handle writing new content to it. These checks are
	// intended to prevent information loss (newly issued certificates), but
	// can be expensive on the storage.
	//
	// Disabling these checks should only be done when the storage
	// can be trusted to have enough capacity and no other problems.
	//
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
	//
	// EXPERIMENTAL. Subject to change.
	DisableStorageClean bool `json:"disable_storage_clean,omitempty"`

	// Enable Encrypted ClientHello (ECH). ECH protects the server name
	// (SNI) and other sensitive parameters of a normally-plaintext TLS
	// ClientHello during a handshake.
	//
	// EXPERIMENTAL: Subject to change.
	EncryptedClientHello *ECH `json:"encrypted_client_hello,omitempty"`

	// The default DNS provider module to use when a DNS module is needed.
	//
	// EXPERIMENTAL: Subject to change.
	DNSRaw json.RawMessage `json:"dns,omitempty" caddy:"namespace=dns.providers inline_key=name"`

	// The default DNS resolvers to use for TLS-related DNS operations, specifically
	// for ACME DNS challenges and ACME server DNS validations.
	// If not specified, the system default resolvers will be used.
	//
	// EXPERIMENTAL: Subject to change.
	Resolvers []string `json:"resolvers,omitempty"`

	dns                any // technically, it should be any/all of the libdns interfaces (RecordSetter, RecordAppender, etc.)
	certificateLoaders []CertificateLoader
	automateNames      map[string]struct{}
	ctx                caddy.Context
	bgCtx              context.Context
	bgCancel           context.CancelFunc
	bgWg               *sync.WaitGroup

	// the certificate cache this app instance provisioned: either the
	// cache the previous config published (reused because its options
	// permit it) or a new one this app created. Start publishes it;
	// Cleanup stops it if it was never published or has been superseded.
	// Everything provisioned by this app reads certificates through this
	// field rather than the published cache, so that provisioning a
	// config that is never committed cannot disturb the running one.
	cache     *certmagic.Cache
	cacheOpts certmagic.CacheOptions

	storageCleanTicker *time.Ticker
	echRotateInterval  time.Duration
	logger             *zap.Logger
	events             *caddyevents.App

	serverNames   map[string]serverNameRegistration
	serverNamesMu *sync.Mutex

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
	t.serverNames = make(map[string]serverNameRegistration)
	t.serverNamesMu = new(sync.Mutex)

	// set up default DNS module, if any, and make sure it implements all the
	// common libdns interfaces, since it could be used for a variety of things
	// (do this before provisioning other modules, since they may rely on this)
	if len(t.DNSRaw) > 0 {
		dnsMod, err := ctx.LoadModule(t, "DNSRaw")
		if err != nil {
			return fmt.Errorf("loading overall DNS provider module: %v", err)
		}
		switch dnsMod.(type) {
		case interface {
			libdns.RecordAppender
			libdns.RecordDeleter
			libdns.RecordGetter
			libdns.RecordSetter
		}:
		default:
			return fmt.Errorf("DNS module does not implement the most common libdns interfaces: %T", dnsMod)
		}
		t.dns = dnsMod
	}

	// set up a new certificate cache; this (re)loads all certificates
	creator := t
	cacheOpts := certmagic.CacheOptions{
		GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
			return creator.appForCache().getConfigForName(cert.Names[0]), nil
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
	cacheOpts = normalizeCacheOptions(cacheOpts)

	// resolve the cache this app will use, without publishing it or
	// stopping the one it may replace: a config that fails to provision
	// or start must leave the committed config's cache intact. Start
	// publishes t.cache; the outgoing app's Cleanup stops the cache it
	// owned once this config is committed.
	t.provisionCertCache(cacheOpts)

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
				if t.automateNames == nil {
					t.automateNames = make(map[string]struct{})
				}
				repl := caddy.NewReplacer()
				for _, sub := range *automateNames {
					t.automateNames[repl.ReplaceAll(sub, "")] = struct{}{}
				}
			} else {
				return fmt.Errorf("loading certificates with 'automate' requires array of strings, got: %T", modIface)
			}
			continue
		}
		t.certificateLoaders = append(t.certificateLoaders, modIface.(CertificateLoader))
	}

	// using the certificate loaders we just initialized, load
	// manual/static (unmanaged) certificates - we do this in
	// provision so that other apps (such as http) can know which
	// certificates have been manually loaded, and also so that
	// commands like validate can be a better test
	magic := certmagic.New(t.cache, certmagic.Config{
		Storage:        ctx.Storage(),
		Logger:         t.logger,
		OnEvent:        t.onEvent,
		ShouldEmitFunc: t.events.ShouldEmit,
		OCSP: certmagic.OCSPConfig{
			DisableStapling: t.DisableOCSPStapling,
		},
		DisableStorageCheck: t.DisableStorageCheck,
	})
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

	// automation/management policies
	if t.Automation == nil {
		t.Automation = new(AutomationConfig)
	}
	t.Automation.defaultPublicAutomationPolicy = new(AutomationPolicy)
	err = t.Automation.defaultPublicAutomationPolicy.Provision(t)
	if err != nil {
		return fmt.Errorf("provisioning default public automation policy: %v", err)
	}
	for n := range t.automateNames {
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

	// session ticket ephemeral keys (STEK) service and provider
	if t.SessionTickets != nil {
		err := t.SessionTickets.provision(ctx)
		if err != nil {
			return fmt.Errorf("provisioning session tickets configuration: %v", err)
		}
	}

	// ECH (Encrypted ClientHello) initialization
	if t.EncryptedClientHello != nil {
		outerNames, err := t.EncryptedClientHello.Provision(ctx)
		if err != nil {
			return fmt.Errorf("provisioning Encrypted ClientHello components: %v", err)
		}

		// outer names should have certificates to reduce client brittleness
		for _, outerName := range outerNames {
			if outerName == "" {
				continue
			}
			if !t.HasCertificateForSubject(outerName) {
				if t.automateNames == nil {
					t.automateNames = make(map[string]struct{})
				}
				t.automateNames[outerName] = struct{}{}
			}
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
	// provisioning succeeded, so this app's cache is now the one the
	// committed config serves from; the cache it replaced (if any) is
	// stopped by the outgoing app's Cleanup, after the config is
	// committed, so that a failure between here and commit cannot leave
	// the still-serving config without certificate maintenance
	t.publishCertCache()

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

	if t.bgCtx == nil {
		parentCtx := t.ctx.Context
		if parentCtx == nil {
			parentCtx = context.Background()
		}
		t.bgCtx, t.bgCancel = context.WithCancel(parentCtx)
	}
	if t.bgWg == nil {
		t.bgWg = new(sync.WaitGroup)
	}

	// now that we are running, and all manual certificates have
	// been loaded, time to load the automated/managed certificates
	err := t.Manage(t.automateNames)
	if err != nil {
		return fmt.Errorf("automate: managing %v: %v", t.automateNames, err)
	}

	if t.EncryptedClientHello != nil {
		echLogger := t.logger.Named("ech")

		// publish ECH configs in the background; does not need to block
		// server startup, as it could take a while; then keep keys rotated
		t.bgWg.Add(1)
		go func(ctx context.Context) {
			defer t.bgWg.Done()
			defer func() {
				if err := recover(); err != nil {
					log.Printf("[PANIC] tls ech publisher: %v\n%s", err, debug.Stack())
				}
			}()

			// publish immediately first
			if err := t.publishECHConfigs(ctx, echLogger); err != nil {
				if !errors.Is(err, context.Canceled) && ctx.Err() == nil {
					echLogger.Error("publication(s) failed", zap.Error(err))
				}
			}

			ticker := time.NewTicker(t.echRotationInterval())
			defer ticker.Stop()

			// then every so often, rotate and publish if needed
			// (both of these functions only do something if needed)
			for {
				select {
				case <-ticker.C:
					// ensure old keys are rotated out
					t.EncryptedClientHello.configsMu.Lock()
					err := t.EncryptedClientHello.rotateECHKeys(t.caddyContext(ctx), echLogger, false)
					t.EncryptedClientHello.configsMu.Unlock()
					if err != nil {
						if !errors.Is(err, context.Canceled) && ctx.Err() == nil {
							echLogger.Error("rotating ECH configs failed", zap.Error(err))
						}
						if ctx.Err() != nil {
							return
						}
						continue
					}
					if ctx.Err() != nil {
						return
					}
					err = t.publishECHConfigs(ctx, echLogger)
					if err != nil {
						if !errors.Is(err, context.Canceled) && ctx.Err() == nil {
							echLogger.Error("publication(s) failed", zap.Error(err))
						}
					}
				case <-ctx.Done():
					return
				}
			}
		}(t.bgCtx)
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
	// cancel all background goroutines (storage cleaner, ECH rotation/publication, etc.)
	if t.bgCancel != nil {
		t.bgCancel()
	}
	if t.storageCleanTicker != nil {
		t.storageCleanTicker.Stop()
	}
	// wait for all background goroutines to finish before returning,
	// ensuring no background storage users are active when module Cleanup() runs
	if t.bgWg != nil {
		t.bgWg.Wait()
	}
	return nil
}

// Cleanup frees up resources allocated during Provision.
func (t *TLS) Cleanup() error {
	// stop the session ticket rotation goroutine
	if t.SessionTickets != nil {
		t.SessionTickets.stop()
	}

	// The app serving the currently-active config, if any. Cleanup runs both
	// for an outgoing app once a new config is committed — where this is the
	// incoming app — and for an app whose own config failed to provision or
	// start, where it is the app still serving. Either way the active app's
	// cache is the one that must survive, and this app's cache is only safe
	// to stop if the active app is not using it.
	var activeApp *TLS
	if active, err := caddy.ActiveContext().AppIfConfigured("tls"); err == nil && active != nil {
		activeApp = active.(*TLS)
	}

	// Snapshot the cache fields under the lock; they are also read by cache
	// maintenance callbacks. ownCache is this app's, activeCache the serving
	// app's.
	certCacheMu.Lock()
	ownCache := t.cache
	var activeCache *certmagic.Cache
	if activeApp != nil && activeApp != t {
		activeCache = activeApp.cache
		// Make sure the published cache is the serving app's cache. Normally
		// it already is, but if this app published its own cache from Start
		// and a later step of the same config load failed, the published
		// cache is one that nothing serves from; put the serving app's cache
		// back so this app's failure leaves no trace.
		if certCache != activeCache {
			certCache = activeCache
			certCacheOpts = activeApp.cacheOpts
			certCacheApp = activeApp
		}
	}
	certCacheMu.Unlock()

	// if a new TLS app was loaded and shares this app's cache, remove
	// certificates from it that are no longer being managed or loaded by the
	// new config; if there is no more TLS app running, then stop cert
	// maintenance and let the cert cache be GC'ed. A new app that replaced
	// the cache needs no eviction: its cache was populated from scratch by
	// its own provisioning, so it holds nothing this app left behind.
	if activeCache != nil && activeCache == ownCache {
		nextTLSApp := activeApp

		// compute which certificates were managed or loaded into the cert cache by this
		// app instance (which is being stopped) that are not managed or loaded by the
		// new app instance (which just started), and remove them from the cache
		var noLongerManaged []certmagic.SubjectIssuer
		var noLongerLoaded []string
		reManage := make(map[string]struct{})
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
					reManage[subj] = struct{}{}
				}
			}
		}
		for hash := range t.loaded {
			if _, ok := nextTLSApp.loaded[hash]; !ok {
				noLongerLoaded = append(noLongerLoaded, hash)
			}
		}

		// remove the certs; this is the cache both apps share, so it is
		// addressed directly rather than through the published pointer
		ownCache.RemoveManaged(noLongerManaged)
		ownCache.Remove(noLongerLoaded)

		// give the new TLS app a "kick" to manage certs that it is configured for
		// with its own configuration instead of the one we just evicted
		if err := nextTLSApp.Manage(reManage); err != nil {
			if c := t.logger.Check(zapcore.ErrorLevel, "re-managing unloaded certificates with new config"); c != nil {
				c.Write(
					zap.Strings("subjects", internal.MaxSizeSubjectsListForLog(reManage, 1000)),
					zap.Error(err),
				)
			}
		}
	}

	// Stop the cache this app owned if nothing serves from it any more —
	// either a reload replaced it, or this app's config was never
	// committed. This is the only place a cache is stopped on a reload, and
	// it runs after the new config is committed, so the cache a live config
	// depends on is never stopped out from under it. Stopping blocks until
	// the maintenance goroutine exits and is done outside the lock so
	// handshakes are not stalled behind it.
	certCacheMu.RLock()
	publishedCache := certCache
	certCacheMu.RUnlock()
	if ownCache != nil && ownCache != publishedCache {
		ownCache.Stop()
	}

	if activeApp == nil {
		// no more TLS app running, so delete in-memory cert cache, if it was
		// created yet, and let it be GC'ed
		certCacheMu.Lock()
		stale := certCache
		certCache = nil
		certCacheApp = nil
		certCacheOpts = certmagic.CacheOptions{}
		certCacheMu.Unlock()
		// the block above only stopped this app's cache if it was *not* the
		// published one, so the published cache still needs stopping here
		if stale != nil {
			stale.Stop()
		}
	}

	return nil
}

// Manage immediately begins managing subjects according to the
// matching automation policy. The subjects are given in a map
// to prevent duplication and also because quick lookups are
// needed to assess wildcard coverage, if any, depending on
// certain config parameters (with lots of subjects, computing
// wildcard coverage over a slice can be highly inefficient).
func (t *TLS) Manage(subjects map[string]struct{}) error {
	// for a large number of names, we can be more memory-efficient
	// by making only one certmagic.Config for all the names that
	// use that config, rather than calling ManageAsync once for
	// every name; so first, bin names by AutomationPolicy
	policyToNames := make(map[*AutomationPolicy][]string)
	for subj := range subjects {
		ap := t.getAutomationPolicyForName(subj)
		// by default, if a wildcard that covers the subj is also being
		// managed, either by a previous call to Manage or by this one,
		// prefer using that over individual certs for its subdomains;
		// but users can disable this and force getting a certificate for
		// subdomains by adding the name to the 'automate' cert loader
		if t.managingWildcardFor(subj, subjects) {
			if _, ok := t.automateNames[subj]; !ok {
				continue
			}
		}
		policyToNames[ap] = append(policyToNames[ap], subj)
	}

	// now that names are grouped by policy, we can simply make one
	// certmagic.Config for each (potentially large) group of names
	// and call ManageAsync just once for the whole batch
	for ap, names := range policyToNames {
		err := ap.magic.ManageAsync(t.ctx.Context, names)
		if err != nil {
			const maxNamesToDisplay = 100
			if len(names) > maxNamesToDisplay {
				names = append(names[:maxNamesToDisplay], fmt.Sprintf("(and %d more...)", len(names)-maxNamesToDisplay))
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

// managingWildcardFor returns true if the app is managing a certificate that covers that
// subject name (including consideration of wildcards), either from its internal list of
// names that it IS managing certs for, from the otherSubjsToManage which includes names
// that WILL be managed, or from names configured in the 'automate' loader.
func (t *TLS) managingWildcardFor(subj string, otherSubjsToManage map[string]struct{}) bool {
	// TODO: we could also consider manually-loaded certs using t.HasCertificateForSubject(),
	// but that does not account for how manually-loaded certs may be restricted as to which
	// hostnames or ClientHellos they can be used with by tags, etc; I don't *think* anyone
	// necessarily wants this anyway, but I thought I'd note this here for now (if we did
	// consider manually-loaded certs, we'd probably want to rename the method since it
	// wouldn't be just about managed certs anymore)

	// IP addresses must match exactly
	if ip := net.ParseIP(subj); ip != nil {
		_, managing := t.managing[subj]
		return managing
	}

	// replace labels of the domain with wildcards until we get a match from names
	// already being managed, those about to be managed in this batch, or those
	// configured for automation
	labels := strings.Split(subj, ".")
	for i := range labels {
		if labels[i] == "*" {
			continue
		}
		labels[i] = "*"
		candidate := strings.Join(labels, ".")
		if _, ok := t.managing[candidate]; ok {
			return true
		}
		if _, ok := otherSubjsToManage[candidate]; ok {
			return true
		}
		if _, ok := t.automateNames[candidate]; ok {
			return true
		}
	}

	return false
}

// RegisterServerNames registers the provided DNS names with the TLS app and
// associates them with the given HTTPS RR ALPN values, if any. This is
// currently used to auto-publish Encrypted ClientHello (ECH) configurations,
// if enabled. Use of this function by apps using the TLS app removes the need
// for the user to redundantly specify domain names in their configuration.
// This function separates hostname and port, keeping only the hostname, and
// filters IP addresses which can't be used with ECH.
//
// EXPERIMENTAL: This function and its semantics/behavior are subject to change.
func (t *TLS) RegisterServerNames(dnsNames, alpnValues []string) {
	t.serverNamesMu.Lock()
	defer t.serverNamesMu.Unlock()

	for _, name := range dnsNames {
		host, _, err := net.SplitHostPort(name)
		if err != nil {
			host = name
		}
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" || certmagic.SubjectIsIP(host) {
			continue
		}

		registration := t.serverNames[host]

		if len(alpnValues) == 0 {
			t.serverNames[host] = registration
			continue
		}

		if registration.alpnValues == nil {
			registration.alpnValues = make(map[string]struct{}, len(alpnValues))
		}
		for _, alpn := range alpnValues {
			if alpn == "" {
				continue
			}
			registration.alpnValues[alpn] = struct{}{}
		}
		t.serverNames[host] = registration
	}
}

func (t *TLS) alpnValuesForServerNames(dnsNames []string) map[string][]string {
	t.serverNamesMu.Lock()
	defer t.serverNamesMu.Unlock()

	result := make(map[string][]string, len(dnsNames))
	for _, name := range dnsNames {
		host, _, err := net.SplitHostPort(name)
		if err != nil {
			host = name
		}
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" {
			continue
		}

		registration, ok := t.serverNames[host]
		if !ok || len(registration.alpnValues) == 0 {
			continue
		}
		result[host] = OrderedHTTPSRRALPN(registration.alpnValues)
	}

	return result
}

// OrderedHTTPSRRALPN returns the HTTPS RR ALPN values in preferred order.
func OrderedHTTPSRRALPN(alpnSet map[string]struct{}) []string {
	if len(alpnSet) == 0 {
		return nil
	}

	knownOrder := append([]string{"h3"}, defaultALPN...)
	ordered := make([]string, 0, len(alpnSet))
	seen := make(map[string]struct{}, len(alpnSet))

	for _, alpn := range knownOrder {
		if _, ok := alpnSet[alpn]; ok {
			ordered = append(ordered, alpn)
			seen[alpn] = struct{}{}
		}
	}

	if len(ordered) == len(alpnSet) {
		return ordered
	}

	var remaining []string
	for alpn := range alpnSet {
		if _, ok := seen[alpn]; ok {
			continue
		}
		remaining = append(remaining, alpn)
	}
	slices.Sort(remaining)

	return append(ordered, remaining...)
}

type serverNameRegistration struct {
	alpnValues map[string]struct{}
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
	certCacheMu.RLock()
	defer certCacheMu.RUnlock()
	return certCache.AllMatchingCertificates(san)
}

func (t *TLS) HasCertificateForSubject(subject string) bool {
	// this app's own cache, not the published one: the question is what
	// this config has loaded or manages, and it is asked during
	// provisioning (by auto-HTTPS and ECH) before this app's cache is
	// published
	certCacheMu.RLock()
	cache := t.cache
	certCacheMu.RUnlock()
	if cache == nil {
		return false
	}
	allMatchingCerts := cache.AllMatchingCertificates(subject)
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
	if t.bgCtx == nil {
		parentCtx := t.ctx.Context
		if parentCtx == nil {
			parentCtx = context.Background()
		}
		t.bgCtx, t.bgCancel = context.WithCancel(parentCtx)
	}
	if t.bgWg == nil {
		t.bgWg = new(sync.WaitGroup)
	}
	t.storageCleanTicker = time.NewTicker(t.storageCleanInterval())
	t.bgWg.Add(1)
	go func(ctx context.Context) {
		defer t.bgWg.Done()
		defer func() {
			if err := recover(); err != nil {
				log.Printf("[PANIC] storage cleaner: %v\n%s", err, debug.Stack())
			}
		}()
		t.cleanStorageUnits(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.storageCleanTicker.C:
				t.cleanStorageUnits(ctx)
			}
		}
	}(t.bgCtx)
}

func (t *TLS) cleanStorageUnits(ctx context.Context) {
	storageCleanMu.Lock()
	defer storageCleanMu.Unlock()

	if err := ctx.Err(); err != nil {
		return
	}

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
	if storage := t.ctx.Storage(); storage != nil {
		err = certmagic.CleanStorage(ctx, storage, options)
		if err != nil {
			if errors.Is(err, context.Canceled) || ctx.Err() != nil {
				return
			}
			// probably don't want to return early, since we should still
			// see if any other storages can get cleaned up
			if c := t.logger.Check(zapcore.ErrorLevel, "could not clean default/global storage"); c != nil {
				c.Write(zap.Error(err))
			}
		}
	}

	// then clean each storage defined in ACME automation policies
	if t.Automation != nil {
		for _, ap := range t.Automation.Policies {
			if ap.storage == nil {
				continue
			}
			if err := certmagic.CleanStorage(ctx, ap.storage, options); err != nil {
				if errors.Is(err, context.Canceled) || ctx.Err() != nil {
					return
				}
				if c := t.logger.Check(zapcore.ErrorLevel, "could not clean storage configured in automation policy"); c != nil {
					c.Write(zap.Error(err))
				}
			}
		}
	}

	if err := ctx.Err(); err != nil {
		return
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

func (t *TLS) echRotationInterval() time.Duration {
	if t.echRotateInterval > 0 {
		return t.echRotateInterval
	}
	return 1 * time.Hour
}

func (t *TLS) caddyContext(ctx context.Context) caddy.Context {
	caddyCtx := t.ctx
	caddyCtx.Context = ctx
	return caddyCtx
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
