package caddytls

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"

	"bitbucket.org/lightcodelabs/caddy2"
	"github.com/go-acme/lego/challenge"
	"github.com/klauspost/cpuid"
	"github.com/mholt/certmagic"
)

func init() {
	caddy2.RegisterModule(caddy2.Module{
		Name: "tls",
		New:  func() (interface{}, error) { return new(TLS), nil },
	})
}

// TLS represents a process-wide TLS configuration.
type TLS struct {
	Certificates map[string]json.RawMessage `json:"certificates"`
	Automation   AutomationConfig           `json:"automation"`

	certificateLoaders []CertificateLoader
	certCache          *certmagic.Cache
}

// Provision sets up the configuration for the TLS app.
func (t *TLS) Provision() error {
	// set up the certificate cache
	// TODO: this makes a new cache every time; better to only make a new
	// cache (or even better, add/remove only what is necessary) if the
	// certificates config has been updated
	t.certCache = certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(cert certmagic.Certificate) (certmagic.Config, error) {
			return t.getConfigForName(cert.Names[0])
		},
	})

	for i, ap := range t.Automation.Policies {
		val, err := caddy2.LoadModuleInline("module", "tls.management", ap.Management)
		if err != nil {
			return fmt.Errorf("loading TLS automation management module: %s", err)
		}
		t.Automation.Policies[i].management = val.(ManagerMaker)
		t.Automation.Policies[i].Management = nil // allow GC to deallocate - TODO: Does this help?
	}

	// certificate loaders
	for modName, rawMsg := range t.Certificates {
		if modName == automateKey {
			continue // special case; these will be loaded in later
		}
		val, err := caddy2.LoadModule("tls.certificates."+modName, rawMsg)
		if err != nil {
			return fmt.Errorf("loading certificate module '%s': %s", modName, err)
		}
		t.certificateLoaders = append(t.certificateLoaders, val.(CertificateLoader))
	}

	return nil
}

// Start activates the TLS module.
func (t *TLS) Start(handle caddy2.Handle) error {
	// load manual/static (unmanaged) certificates
	for _, loader := range t.certificateLoaders {
		certs, err := loader.LoadCertificates()
		if err != nil {
			return fmt.Errorf("loading certificates: %v", err)
		}
		magic := certmagic.New(t.certCache, certmagic.Config{
			Storage: caddy2.GetStorage(),
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
	return nil
}

// Manage immediately begins managing names according to the
// matching automation policy.
func (t *TLS) Manage(names []string) error {
	for _, name := range names {
		ap := t.getAutomationPolicyForName(name)
		magic := certmagic.New(t.certCache, ap.makeCertMagicConfig())
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
	magic := certmagic.New(t.certCache, ap.makeCertMagicConfig())
	return magic.HandleHTTPChallenge(w, r)
}

func (t *TLS) getConfigForName(name string) (certmagic.Config, error) {
	ap := t.getAutomationPolicyForName(name)
	return ap.makeCertMagicConfig(), nil
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
	mgmt := new(acmeManagerMaker)
	mgmt.setDefaults()
	return AutomationPolicy{management: mgmt}
}

// CertificateLoader is a type that can load certificates.
type CertificateLoader interface {
	LoadCertificates() ([]tls.Certificate, error)
}

// AutomationConfig designates configuration for the
// construction and use of ACME clients.
type AutomationConfig struct {
	Policies []AutomationPolicy `json:"policies,omitempty"`
}

// AutomationPolicy designates the policy for automating the
// management of managed TLS certificates.
type AutomationPolicy struct {
	Hosts      []string        `json:"hosts,omitempty"`
	Management json.RawMessage `json:"management"`

	management ManagerMaker
}

func (ap AutomationPolicy) makeCertMagicConfig() certmagic.Config {
	// default manager (ACME) is a special case because of how CertMagic is designed
	// TODO: refactor certmagic so that ACME manager is not a special case by extracting
	// its config fields out of the certmagic.Config struct, or something...
	if acmeMgmt, ok := ap.management.(*acmeManagerMaker); ok {
		return acmeMgmt.makeCertMagicConfig()
	}

	return certmagic.Config{
		NewManager: ap.management.newManager,
	}
}

// ChallengesConfig configures the ACME challenges.
type ChallengesConfig struct {
	HTTP    HTTPChallengeConfig    `json:"http"`
	TLSALPN TLSALPNChallengeConfig `json:"tls-alpn"`
	DNS     json.RawMessage        `json:"dns,omitempty"`

	dns challenge.Provider
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
	// TODO: MaxCertificates state might not endure reloads...
	// MaxCertificates int    `json:"max_certificates,omitempty"`
	AskURL      string `json:"ask_url,omitempty"`
	AskStarlark string `json:"ask_starlark,omitempty"`
}

// ManagerMaker makes a certificate manager.
type ManagerMaker interface {
	newManager(interactive bool) (certmagic.Manager, error)
}

// supportedCipherSuites is the unordered map of cipher suite
// string names to their definition in crypto/tls.
// TODO: might not be needed much longer, see:
// https://github.com/golang/go/issues/30325
var supportedCipherSuites = map[string]uint16{
	"ECDHE_ECDSA_AES256_GCM_SHA384":      tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	"ECDHE_RSA_AES256_GCM_SHA384":        tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	"ECDHE_ECDSA_AES128_GCM_SHA256":      tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	"ECDHE_RSA_AES128_GCM_SHA256":        tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"ECDHE_ECDSA_WITH_CHACHA20_POLY1305": tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	"ECDHE_RSA_WITH_CHACHA20_POLY1305":   tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	"ECDHE_RSA_AES256_CBC_SHA":           tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	"ECDHE_RSA_AES128_CBC_SHA":           tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	"ECDHE_ECDSA_AES256_CBC_SHA":         tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	"ECDHE_ECDSA_AES128_CBC_SHA":         tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	"RSA_AES256_CBC_SHA":                 tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	"RSA_AES128_CBC_SHA":                 tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	"ECDHE_RSA_3DES_EDE_CBC_SHA":         tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	"RSA_3DES_EDE_CBC_SHA":               tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
}

// defaultCipherSuites is the ordered list of all the cipher
// suites we want to support by default, assuming AES-NI
// (hardware acceleration for AES).
var defaultCipherSuitesWithAESNI = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
}

// defaultCipherSuites is the ordered list of all the cipher
// suites we want to support by default, assuming lack of
// AES-NI (NO hardware acceleration for AES).
var defaultCipherSuitesWithoutAESNI = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
}

// getOptimalDefaultCipherSuites returns an appropriate cipher
// suite to use depending on the hardware support for AES.
//
// See https://github.com/mholt/caddy/issues/1674
func getOptimalDefaultCipherSuites() []uint16 {
	if cpuid.CPU.AesNi() {
		return defaultCipherSuitesWithAESNI
	}
	return defaultCipherSuitesWithoutAESNI
}

// supportedCurves is the unordered map of supported curves.
// https://golang.org/pkg/crypto/tls/#CurveID
var supportedCurves = map[string]tls.CurveID{
	"X25519": tls.X25519,
	"P256":   tls.CurveP256,
	"P384":   tls.CurveP384,
	"P521":   tls.CurveP521,
}

// defaultCurves is the list of only the curves we want to use
// by default, in descending order of preference.
//
// This list should only include curves which are fast by design
// (e.g. X25519) and those for which an optimized assembly
// implementation exists (e.g. P256). The latter ones can be
// found here:
// https://github.com/golang/go/tree/master/src/crypto/elliptic
var defaultCurves = []tls.CurveID{
	tls.X25519,
	tls.CurveP256,
}

// supportedProtocols is a map of supported protocols.
// HTTP/2 only supports TLS 1.2 and higher.
var supportedProtocols = map[string]uint16{
	"tls1.0": tls.VersionTLS10,
	"tls1.1": tls.VersionTLS11,
	"tls1.2": tls.VersionTLS12,
	"tls1.3": tls.VersionTLS13,
}

const automateKey = "automate"
