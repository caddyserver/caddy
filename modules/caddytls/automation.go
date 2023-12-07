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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez"
	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
)

// AutomationConfig governs the automated management of TLS certificates.
type AutomationConfig struct {
	// The list of automation policies. The first policy matching
	// a certificate or subject name will be applied.
	Policies []*AutomationPolicy `json:"policies,omitempty"`

	// On-Demand TLS defers certificate operations to the
	// moment they are needed, e.g. during a TLS handshake.
	// Useful when you don't know all the hostnames at
	// config-time, or when you are not in control of the
	// domain names you are managing certificates for.
	// In 2015, Caddy became the first web server to
	// implement this experimental technology.
	//
	// Note that this field does not enable on-demand TLS;
	// it only configures it for when it is used. To enable
	// it, create an automation policy with `on_demand`.
	OnDemand *OnDemandConfig `json:"on_demand,omitempty"`

	// Caddy staples OCSP (and caches the response) for all
	// qualifying certificates by default. This setting
	// changes how often it scans responses for freshness,
	// and updates them if they are getting stale. Default: 1h
	OCSPCheckInterval caddy.Duration `json:"ocsp_interval,omitempty"`

	// Every so often, Caddy will scan all loaded, managed
	// certificates for expiration. This setting changes how
	// frequently the scan for expiring certificates is
	// performed. Default: 10m
	RenewCheckInterval caddy.Duration `json:"renew_interval,omitempty"`

	// How often to scan storage units for old or expired
	// assets and remove them. These scans exert lots of
	// reads (and list operations) on the storage module, so
	// choose a longer interval for large deployments.
	// Default: 24h
	//
	// Storage will always be cleaned when the process first
	// starts. Then, a new cleaning will be started this
	// duration after the previous cleaning started if the
	// previous cleaning finished in less than half the time
	// of this interval (otherwise next start will be skipped).
	StorageCleanInterval caddy.Duration `json:"storage_clean_interval,omitempty"`

	defaultPublicAutomationPolicy   *AutomationPolicy
	defaultInternalAutomationPolicy *AutomationPolicy // only initialized if necessary
}

// AutomationPolicy designates the policy for automating the
// management (obtaining, renewal, and revocation) of managed
// TLS certificates.
//
// An AutomationPolicy value is not valid until it has been
// provisioned; use the `AddAutomationPolicy()` method on the
// TLS app to properly provision a new policy.
type AutomationPolicy struct {
	// Which subjects (hostnames or IP addresses) this policy applies to.
	//
	// This list is a filter, not a command. In other words, it is used
	// only to filter whether this policy should apply to a subject that
	// needs a certificate; it does NOT command the TLS app to manage a
	// certificate for that subject. To have Caddy automate a certificate
	// or specific subjects, use the "automate" certificate loader module
	// of the TLS app.
	SubjectsRaw []string `json:"subjects,omitempty"`

	// The modules that may issue certificates. Default: internal if all
	// subjects do not qualify for public certificates; othewise acme and
	// zerossl.
	IssuersRaw []json.RawMessage `json:"issuers,omitempty" caddy:"namespace=tls.issuance inline_key=module"`

	// Modules that can get a custom certificate to use for any
	// given TLS handshake at handshake-time. Custom certificates
	// can be useful if another entity is managing certificates
	// and Caddy need only get it and serve it. Specifying a Manager
	// enables on-demand TLS, i.e. it has the side-effect of setting
	// the on_demand parameter to `true`.
	//
	// TODO: This is an EXPERIMENTAL feature. Subject to change or removal.
	ManagersRaw []json.RawMessage `json:"get_certificate,omitempty" caddy:"namespace=tls.get_certificate inline_key=via"`

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

	// If true, certificates will be managed "on demand"; that is, during
	// TLS handshakes or when needed, as opposed to at startup or config
	// load. This enables On-Demand TLS for this policy.
	OnDemand bool `json:"on_demand,omitempty"`

	// Disables OCSP stapling. Disabling OCSP stapling puts clients at
	// greater risk, reduces their privacy, and usually lowers client
	// performance. It is NOT recommended to disable this unless you
	// are able to justify the costs.
	// EXPERIMENTAL. Subject to change.
	DisableOCSPStapling bool `json:"disable_ocsp_stapling,omitempty"`

	// Overrides the URLs of OCSP responders embedded in certificates.
	// Each key is a OCSP server URL to override, and its value is the
	// replacement. An empty value will disable querying of that server.
	// EXPERIMENTAL. Subject to change.
	OCSPOverrides map[string]string `json:"ocsp_overrides,omitempty"`

	// Issuers and Managers store the decoded issuer and manager modules;
	// they are only used to populate an underlying certmagic.Config's
	// fields during provisioning so that the modules can survive a
	// re-provisioning.
	Issuers  []certmagic.Issuer  `json:"-"`
	Managers []certmagic.Manager `json:"-"`

	subjects []string
	magic    *certmagic.Config
	storage  certmagic.Storage
}

// Provision sets up ap and builds its underlying CertMagic config.
func (ap *AutomationPolicy) Provision(tlsApp *TLS) error {
	// replace placeholders in subjects to allow environment variables
	repl := caddy.NewReplacer()
	subjects := make([]string, len(ap.SubjectsRaw))
	for i, sub := range ap.SubjectsRaw {
		subjects[i] = repl.ReplaceAll(sub, "")
	}
	ap.subjects = subjects

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

	// we don't store loaded modules directly in the certmagic config since
	// policy provisioning may happen more than once (during auto-HTTPS) and
	// loading a module clears its config bytes; thus, load the module and
	// store them on the policy before putting it on the config

	// load and provision any cert manager modules
	if ap.ManagersRaw != nil {
		vals, err := tlsApp.ctx.LoadModule(ap, "ManagersRaw")
		if err != nil {
			return fmt.Errorf("loading external certificate manager modules: %v", err)
		}
		for _, getCertVal := range vals.([]any) {
			ap.Managers = append(ap.Managers, getCertVal.(certmagic.Manager))
		}
	}

	// load and provision any explicitly-configured issuer modules
	if ap.IssuersRaw != nil {
		val, err := tlsApp.ctx.LoadModule(ap, "IssuersRaw")
		if err != nil {
			return fmt.Errorf("loading TLS automation management module: %s", err)
		}
		for _, issVal := range val.([]any) {
			ap.Issuers = append(ap.Issuers, issVal.(certmagic.Issuer))
		}
	}

	issuers := ap.Issuers
	if len(issuers) == 0 {
		var err error
		issuers, err = DefaultIssuersProvisioned(tlsApp.ctx)
		if err != nil {
			return err
		}
	}

	keyType := ap.KeyType
	if keyType != "" {
		var err error
		keyType, err = caddy.NewReplacer().ReplaceOrErr(ap.KeyType, true, true)
		if err != nil {
			return fmt.Errorf("invalid key type %s: %s", ap.KeyType, err)
		}
		if _, ok := supportedCertKeyTypes[keyType]; !ok {
			return fmt.Errorf("unrecognized key type: %s", keyType)
		}
	}
	keySource := certmagic.StandardKeyGenerator{
		KeyType: supportedCertKeyTypes[keyType],
	}

	storage := ap.storage
	if storage == nil {
		storage = tlsApp.ctx.Storage()
	}

	// on-demand TLS
	var ond *certmagic.OnDemandConfig
	if ap.OnDemand || len(ap.Managers) > 0 {
		// ask endpoint is now required after a number of negligence cases causing abuse;
		// but is still allowed for explicit subjects (non-wildcard, non-unbounded),
		// for the internal issuer since it doesn't cause ACME issuer pressure
		if ap.isWildcardOrDefault() && !ap.onlyInternalIssuer() && (tlsApp.Automation == nil || tlsApp.Automation.OnDemand == nil || tlsApp.Automation.OnDemand.Ask == "") {
			return fmt.Errorf("on-demand TLS cannot be enabled without an 'ask' endpoint to prevent abuse; please refer to documentation for details")
		}
		ond = &certmagic.OnDemandConfig{
			DecisionFunc: func(ctx context.Context, name string) error {
				if tlsApp.Automation == nil || tlsApp.Automation.OnDemand == nil {
					return nil
				}
				if err := onDemandAskRequest(ctx, tlsApp.logger, tlsApp.Automation.OnDemand.Ask, name); err != nil {
					// distinguish true errors from denials, because it's important to elevate actual errors
					if errors.Is(err, errAskDenied) {
						tlsApp.logger.Debug("certificate issuance denied",
							zap.String("ask_endpoint", tlsApp.Automation.OnDemand.Ask),
							zap.String("domain", name),
							zap.Error(err))
					} else {
						tlsApp.logger.Error("request to 'ask' endpoint failed",
							zap.String("ask_endpoint", tlsApp.Automation.OnDemand.Ask),
							zap.String("domain", name),
							zap.Error(err))
					}
					return err
				}
				// check the rate limiter last because
				// doing so makes a reservation
				if !onDemandRateLimiter.Allow() {
					return fmt.Errorf("on-demand rate limit exceeded")
				}
				return nil
			},
			Managers: ap.Managers,
		}
	}

	template := certmagic.Config{
		MustStaple:         ap.MustStaple,
		RenewalWindowRatio: ap.RenewalWindowRatio,
		KeySource:          keySource,
		OnEvent:            tlsApp.onEvent,
		OnDemand:           ond,
		OCSP: certmagic.OCSPConfig{
			DisableStapling:    ap.DisableOCSPStapling,
			ResponderOverrides: ap.OCSPOverrides,
		},
		Storage: storage,
		Issuers: issuers,
		Logger:  tlsApp.logger,
	}
	certCacheMu.RLock()
	ap.magic = certmagic.New(certCache, template)
	certCacheMu.RUnlock()

	// sometimes issuers may need the parent certmagic.Config in
	// order to function properly (for example, ACMEIssuer needs
	// access to the correct storage and cache so it can solve
	// ACME challenges -- it's an annoying, inelegant circular
	// dependency that I don't know how to resolve nicely!)
	for _, issuer := range ap.magic.Issuers {
		if annoying, ok := issuer.(ConfigSetter); ok {
			annoying.SetConfig(ap.magic)
		}
	}

	return nil
}

// Subjects returns the list of subjects with all placeholders replaced.
func (ap *AutomationPolicy) Subjects() []string {
	return ap.subjects
}

func (ap *AutomationPolicy) onlyInternalIssuer() bool {
	if len(ap.Issuers) != 1 {
		return false
	}
	_, ok := ap.Issuers[0].(*InternalIssuer)
	return ok
}

// isWildcardOrDefault determines if the subjects include any wildcard domains,
// or is the "default" policy (i.e. no subjects) which is unbounded.
func (ap *AutomationPolicy) isWildcardOrDefault() bool {
	isWildcardOrDefault := false
	if len(ap.subjects) == 0 {
		isWildcardOrDefault = true
	}
	for _, sub := range ap.subjects {
		if strings.HasPrefix(sub, "*") {
			isWildcardOrDefault = true
			break
		}
	}
	return isWildcardOrDefault
}

// DefaultIssuers returns empty Issuers (not provisioned) to be used as defaults.
// This function is experimental and has no compatibility promises.
func DefaultIssuers() []certmagic.Issuer {
	return []certmagic.Issuer{
		new(ACMEIssuer),
		&ZeroSSLIssuer{ACMEIssuer: new(ACMEIssuer)},
	}
}

// DefaultIssuersProvisioned returns empty but provisioned default Issuers from
// DefaultIssuers(). This function is experimental and has no compatibility promises.
func DefaultIssuersProvisioned(ctx caddy.Context) ([]certmagic.Issuer, error) {
	issuers := DefaultIssuers()
	for i, iss := range issuers {
		if prov, ok := iss.(caddy.Provisioner); ok {
			err := prov.Provision(ctx)
			if err != nil {
				return nil, fmt.Errorf("provisioning default issuer %d: %T: %v", i, iss, err)
			}
		}
	}
	return issuers, nil
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
	//
	// NOTE: DNS providers are currently being upgraded,
	// and this API is subject to change, but should be
	// stabilized soon.
	DNS *DNSChallengeConfig `json:"dns,omitempty"`

	// Optionally customize the host to which a listener
	// is bound if required for solving a challenge.
	BindHost string `json:"bind_host,omitempty"`
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

// DNSChallengeConfig configures the ACME DNS challenge.
//
// NOTE: This API is still experimental and is subject to change.
type DNSChallengeConfig struct {
	// The DNS provider module to use which will manage
	// the DNS records relevant to the ACME challenge.
	ProviderRaw json.RawMessage `json:"provider,omitempty" caddy:"namespace=dns.providers inline_key=name"`

	// The TTL of the TXT record used for the DNS challenge.
	TTL caddy.Duration `json:"ttl,omitempty"`

	// How long to wait before starting propagation checks.
	// Default: 0 (no wait).
	PropagationDelay caddy.Duration `json:"propagation_delay,omitempty"`

	// Maximum time to wait for temporary DNS record to appear.
	// Set to -1 to disable propagation checks.
	// Default: 2 minutes.
	PropagationTimeout caddy.Duration `json:"propagation_timeout,omitempty"`

	// Custom DNS resolvers to prefer over system/built-in defaults.
	// Often necessary to configure when using split-horizon DNS.
	Resolvers []string `json:"resolvers,omitempty"`

	// Override the domain to use for the DNS challenge. This
	// is to delegate the challenge to a different domain,
	// e.g. one that updates faster or one with a provider API.
	OverrideDomain string `json:"override_domain,omitempty"`

	solver acmez.Solver
}

// OnDemandConfig configures on-demand TLS, for obtaining
// needed certificates at handshake-time. Because this
// feature can easily be abused, you should use this to
// establish rate limits and/or an internal endpoint that
// Caddy can "ask" if it should be allowed to manage
// certificates for a given hostname.
type OnDemandConfig struct {
	// REQUIRED. If Caddy needs to load a certificate from
	// storage or obtain/renew a certificate during a TLS
	// handshake, it will perform a quick HTTP request to
	// this URL to check if it should be allowed to try to
	// get a certificate for the name in the "domain" query
	// string parameter, like so: `?domain=example.com`.
	// The endpoint must return a 200 OK status if a certificate
	// is allowed; anything else will cause it to be denied.
	// Redirects are not followed.
	Ask string `json:"ask,omitempty"`

	// DEPRECATED. An optional rate limit to throttle
	// the checking of storage and the issuance of
	// certificates from handshakes if not already in
	// storage. WILL BE REMOVED IN A FUTURE RELEASE.
	RateLimit *RateLimit `json:"rate_limit,omitempty"`
}

// DEPRECATED. RateLimit specifies an interval with optional burst size.
type RateLimit struct {
	// A duration value. Storage may be checked and a certificate may be
	// obtained 'burst' times during this interval.
	Interval caddy.Duration `json:"interval,omitempty"`

	// How many times during an interval storage can be checked or a
	// certificate can be obtained.
	Burst int `json:"burst,omitempty"`
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
