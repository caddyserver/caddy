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
	"net"
	"slices"
	"strings"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v3"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

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
	// subjects do not qualify for public certificates; otherwise acme and
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

	// If true, private keys already existing in storage
	// will be reused. Otherwise, a new key will be
	// created for every new certificate to mitigate
	// pinning and reduce the scope of key compromise.
	// TEMPORARY: Key pinning is against industry best practices.
	// This property will likely be removed in the future.
	// Do not rely on it forever; watch the release notes.
	ReusePrivateKeys bool `json:"reuse_private_keys,omitempty"`

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

	// Whether this policy had explicit managers configured directly on it.
	hadExplicitManagers bool
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
		ap.hadExplicitManagers = true
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
		// permission module is now required after a number of negligence cases that allowed abuse;
		// but it may still be optional for explicit subjects (bounded, non-wildcard), for the
		// internal issuer since it doesn't cause public PKI pressure on ACME servers; subtly, it
		// is useful to allow on-demand TLS to be enabled so Managers can be used, but to still
		// prevent issuance from Issuers (when Managers don't provide a certificate) if there's no
		// permission module configured
		noProtections := ap.isWildcardOrDefault() && !ap.onlyInternalIssuer() && (tlsApp.Automation == nil || tlsApp.Automation.OnDemand == nil || tlsApp.Automation.OnDemand.permission == nil)
		failClosed := noProtections && !ap.hadExplicitManagers // don't allow on-demand issuance (other than implicit managers) if no managers have been explicitly configured
		if noProtections {
			if !ap.hadExplicitManagers {
				// no managers, no explicitly-configured permission module, this is a config error
				return fmt.Errorf("on-demand TLS cannot be enabled without a permission module to prevent abuse; please refer to documentation for details")
			}
			// allow on-demand to be enabled but only for the purpose of the Managers; issuance won't be allowed from Issuers
			tlsApp.logger.Warn("on-demand TLS can only get certificates from the configured external manager(s) because no ask endpoint / permission module is specified")
		}
		ond = &certmagic.OnDemandConfig{
			DecisionFunc: func(ctx context.Context, name string) error {
				if failClosed {
					return fmt.Errorf("no permission module configured; certificates not allowed except from external Managers")
				}
				if tlsApp.Automation == nil || tlsApp.Automation.OnDemand == nil {
					return nil
				}

				// logging the remote IP can be useful for servers that want to count
				// attempts from clients to detect patterns of abuse -- it should NOT be
				// used solely for decision making, however
				var remoteIP string
				if hello, ok := ctx.Value(certmagic.ClientHelloInfoCtxKey).(*tls.ClientHelloInfo); ok && hello != nil {
					if remote := hello.Conn.RemoteAddr(); remote != nil {
						remoteIP, _, _ = net.SplitHostPort(remote.String())
					}
				}
				if c := tlsApp.logger.Check(zapcore.DebugLevel, "asking for permission for on-demand certificate"); c != nil {
					c.Write(
						zap.String("remote_ip", remoteIP),
						zap.String("domain", name),
					)
				}

				// ask the permission module if this cert is allowed
				if err := tlsApp.Automation.OnDemand.permission.CertificateAllowed(ctx, name); err != nil {
					// distinguish true errors from denials, because it's important to elevate actual errors
					if errors.Is(err, ErrPermissionDenied) {
						if c := tlsApp.logger.Check(zapcore.DebugLevel, "on-demand certificate issuance denied"); c != nil {
							c.Write(
								zap.String("domain", name),
								zap.Error(err),
							)
						}
					} else {
						if c := tlsApp.logger.Check(zapcore.ErrorLevel, "failed to get permission for on-demand certificate"); c != nil {
							c.Write(
								zap.String("domain", name),
								zap.Error(err),
							)
						}
					}
					return err
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
		ReusePrivateKeys:   ap.ReusePrivateKeys,
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

// AllInternalSubjects returns true if all the subjects on this policy are internal.
func (ap *AutomationPolicy) AllInternalSubjects() bool {
	return !slices.ContainsFunc(ap.subjects, func(s string) bool {
		return !certmagic.SubjectIsInternal(s)
	})
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
func DefaultIssuers(userEmail string) []certmagic.Issuer {
	issuers := []certmagic.Issuer{new(ACMEIssuer)}
	if strings.TrimSpace(userEmail) != "" {
		issuers = append(issuers, &ACMEIssuer{
			CA:    certmagic.ZeroSSLProductionCA,
			Email: userEmail,
		})
	}
	return issuers
}

// DefaultIssuersProvisioned returns empty but provisioned default Issuers from
// DefaultIssuers(). This function is experimental and has no compatibility promises.
func DefaultIssuersProvisioned(ctx caddy.Context) ([]certmagic.Issuer, error) {
	issuers := DefaultIssuers("")
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
	// Required.
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

// ConfigSetter is implemented by certmagic.Issuers that
// need access to a parent certmagic.Config as part of
// their provisioning phase. For example, the ACMEIssuer
// requires a config so it can access storage and the
// cache to solve ACME challenges.
type ConfigSetter interface {
	SetConfig(cfg *certmagic.Config)
}
