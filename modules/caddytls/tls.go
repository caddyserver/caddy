package caddytls

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/caddyserver/caddy"
	"github.com/go-acme/lego/challenge"
	"github.com/mholt/certmagic"
	"golang.org/x/time/rate"
)

func init() {
	caddy.RegisterModule(caddy.Module{
		Name: "tls",
		New:  func() interface{} { return new(TLS) },
	})
}

// TLS represents a process-wide TLS configuration.
type TLS struct {
	Certificates   map[string]json.RawMessage `json:"certificates,omitempty"`
	Automation     AutomationConfig           `json:"automation,omitempty"`
	SessionTickets SessionTicketService       `json:"session_tickets,omitempty"`

	certificateLoaders []CertificateLoader
	certCache          *certmagic.Cache
	ctx                caddy.Context
}

// Provision sets up the configuration for the TLS app.
func (t *TLS) Provision(ctx caddy.Context) error {
	t.ctx = ctx

	// set up the certificate cache
	// TODO: this makes a new cache every time; better to only make a new
	// cache (or even better, add/remove only what is necessary) if the
	// certificates config has been updated
	t.certCache = certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(cert certmagic.Certificate) (certmagic.Config, error) {
			return t.getConfigForName(cert.Names[0])
		},
	})

	// automation/management policies
	for i, ap := range t.Automation.Policies {
		val, err := ctx.LoadModuleInline("module", "tls.management", ap.ManagementRaw)
		if err != nil {
			return fmt.Errorf("loading TLS automation management module: %s", err)
		}
		t.Automation.Policies[i].Management = val.(managerMaker)
		t.Automation.Policies[i].ManagementRaw = nil // allow GC to deallocate - TODO: Does this help?
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
	err := t.SessionTickets.provision(ctx)
	if err != nil {
		return fmt.Errorf("provisioning session tickets configuration: %v", err)
	}

	// on-demand rate limiting
	if t.Automation.OnDemand != nil && t.Automation.OnDemand.RateLimit != nil {
		limit := rate.Every(time.Duration(t.Automation.OnDemand.RateLimit.Interval))
		// TODO: Burst size is not updated, see https://github.com/golang/go/issues/23575
		onDemandRateLimiter.SetLimit(limit)
	} else {
		// if no rate limit is specified, be sure to remove any existing limit
		onDemandRateLimiter.SetLimit(0)
	}

	return nil
}

// Start activates the TLS module.
func (t *TLS) Start() error {
	// load manual/static (unmanaged) certificates
	for _, loader := range t.certificateLoaders {
		certs, err := loader.LoadCertificates()
		if err != nil {
			return fmt.Errorf("loading certificates: %v", err)
		}
		magic := certmagic.New(t.certCache, certmagic.Config{
			Storage: t.ctx.Storage(),
		})
		for _, cert := range certs {
			err := magic.CacheUnmanagedTLSCertificate(cert)
			if err != nil {
				return fmt.Errorf("caching unmanaged certificate: %v", err)
			}
		}
	}

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
	t.Certificates = nil // allow GC to deallocate - TODO: Does this help?

	return nil
}

// Stop stops the TLS module and cleans up any allocations.
func (t *TLS) Stop() error {
	if t.certCache != nil {
		// TODO: ensure locks are cleaned up too... maybe in certmagic though
		t.certCache.Stop()
	}
	t.SessionTickets.stop()
	return nil
}

// Manage immediately begins managing names according to the
// matching automation policy.
func (t *TLS) Manage(names []string) error {
	for _, name := range names {
		ap := t.getAutomationPolicyForName(name)
		magic := certmagic.New(t.certCache, ap.makeCertMagicConfig(t.ctx))
		err := magic.Manage([]string{name})
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

	// default automation policy
	mgmt := new(ACMEManagerMaker)
	mgmt.SetDefaults()
	return AutomationPolicy{Management: mgmt}
}

// CertificateLoader is a type that can load certificates.
type CertificateLoader interface {
	LoadCertificates() ([]tls.Certificate, error)
}

// AutomationConfig designates configuration for the
// construction and use of ACME clients.
type AutomationConfig struct {
	Policies []AutomationPolicy `json:"policies,omitempty"`
	OnDemand *OnDemandConfig    `json:"on_demand,omitempty"`
}

// AutomationPolicy designates the policy for automating the
// management of managed TLS certificates.
type AutomationPolicy struct {
	Hosts         []string        `json:"hosts,omitempty"`
	ManagementRaw json.RawMessage `json:"management,omitempty"`

	Management managerMaker `json:"-"`
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
		NewManager: ap.Management.newManager,
	}
}

// ChallengesConfig configures the ACME challenges.
type ChallengesConfig struct {
	HTTP    HTTPChallengeConfig    `json:"http"`
	TLSALPN TLSALPNChallengeConfig `json:"tls-alpn"`
	DNSRaw  json.RawMessage        `json:"dns,omitempty"`

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

// managerMaker makes a certificate manager.
type managerMaker interface {
	newManager(interactive bool) (certmagic.Manager, error)
}

// These perpetual values are used for on-demand TLS.
var (
	onDemandRateLimiter = rate.NewLimiter(0, 1)
	onDemandAskClient   = &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return fmt.Errorf("following http redirects is not allowed")
		},
	}
)

const automateKey = "automate"
