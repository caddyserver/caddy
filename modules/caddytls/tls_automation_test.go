package caddytls

import (
	"testing"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

func TestAutomationPolicyIDNIssuerSelection(t *testing.T) {
	for _, tc := range []struct {
		name         string
		subject      string
		serverName   string
		canonical    string
		wantFallback bool
	}{
		{name: "Unicode", subject: "bücher.example", serverName: "bücher.example", canonical: "xn--bcher-kva.example"},
		{name: "A-label", subject: "bücher.example", serverName: "xn--bcher-kva.example", canonical: "xn--bcher-kva.example"},
		{name: "A-label policy", subject: "xn--bcher-kva.example", serverName: "bücher.example", canonical: "xn--bcher-kva.example"},
		{name: "uppercase A-label", subject: "bücher.example", serverName: "XN--BCHER-KVA.EXAMPLE", canonical: "xn--bcher-kva.example"},
		{name: "uppercase Unicode", subject: "BÜCHER.example", serverName: "BÜCHER.example", canonical: "xn--bcher-kva.example"},
		{name: "mapped input", subject: "example.com", serverName: "ｅxample.com", canonical: "example.com"},
		{name: "mapped policy", subject: "ｅxample.com", serverName: "example.com", canonical: "example.com"},
		{name: "Unicode separator", subject: "bücher.example", serverName: "bücher。example", canonical: "xn--bcher-kva.example"},
		{name: "normalized Unicode", subject: "bu\u0308cher.example", serverName: "bücher.example", canonical: "xn--bcher-kva.example"},
		{name: "trimmed input", subject: "bücher.example", serverName: " bücher.example ", canonical: "xn--bcher-kva.example"},
		{name: "wildcard Unicode", subject: "*.bücher.example", serverName: "shop.bücher.example", canonical: "shop.xn--bcher-kva.example"},
		{name: "wildcard A-label", subject: "*.bücher.example", serverName: "shop.xn--bcher-kva.example", canonical: "shop.xn--bcher-kva.example"},
		{name: "wildcard uppercase Unicode", subject: "*.BÜCHER.example", serverName: "shop.bücher.example", canonical: "shop.xn--bcher-kva.example"},
		{name: "wildcard Unicode separator", subject: "*。BÜCHER.example", serverName: "shop.bücher.example", canonical: "shop.xn--bcher-kva.example"},
		{name: "wildcard apex excluded", subject: "*.bücher.example", serverName: "bücher.example", canonical: "xn--bcher-kva.example", wantFallback: true},
		{name: "wildcard multiple labels excluded", subject: "*.bücher.example", serverName: "deep.shop.bücher.example", canonical: "deep.shop.xn--bcher-kva.example", wantFallback: true},
		{name: "unrelated name", subject: "bücher.example", serverName: "other.example", canonical: "other.example", wantFallback: true},
		{name: "placeholder policy", subject: "{env.CADDY_TEST_AUTOMATION_IDN}", serverName: "bücher.example", canonical: "xn--bcher-kva.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CADDY_TEST_AUTOMATION_IDN", "bücher.example")
			specificIssuer := newAutomationTestIssuer(t, "specific")
			fallbackIssuer := newAutomationTestIssuer(t, "fallback")
			specific := &AutomationPolicy{
				SubjectsRaw: []string{tc.subject},
				OnDemand:    true,
				Issuers:     []certmagic.Issuer{specificIssuer},
			}
			fallback := &AutomationPolicy{OnDemand: true, Issuers: []certmagic.Issuer{fallbackIssuer}}
			tlsApp := automationTestTLS(t, specific, fallback)
			if cfg := tlsApp.getConfigForName(specific.subjects[0]); cfg.Issuers[0] != specificIssuer {
				t.Fatal("configured subject, including any wildcard, must select its own issuer")
			}
			wantIssuer, otherIssuer := specificIssuer, fallbackIssuer
			if tc.wantFallback {
				wantIssuer, otherIssuer = fallbackIssuer, specificIssuer
			}

			// Start with an empty cache and the supplied SNI, then repeat using
			// its canonical A-label to check the certificate cached by that first request.
			for _, name := range []string{tc.serverName, tc.canonical} {
				cfg := tlsApp.getConfigForName(name)
				if len(cfg.Issuers) != 1 || cfg.Issuers[0] != wantIssuer {
					t.Errorf("SNI %q selected issuers %v, want %s", name, cfg.Issuers, wantIssuer.IssuerKey())
				}
				cert, err := automationTestGetCertificate(cfg, name)
				if err != nil {
					t.Fatalf("getting certificate for %q: %v", name, err)
				}
				if err := cert.Leaf.CheckSignatureFrom(wantIssuer.root); err != nil {
					t.Errorf("certificate for %q was not signed by %s: %v", name, wantIssuer.IssuerKey(), err)
				}
				if err := cert.Leaf.VerifyHostname(tc.canonical); err != nil {
					t.Errorf("certificate must cover canonical name: %v", err)
				}
			}
			if wantIssuer.calls != 1 || otherIssuer.calls != 0 {
				t.Errorf("expected one issuance from %s only, got specific=%d fallback=%d",
					wantIssuer.IssuerKey(), specificIssuer.calls, fallbackIssuer.calls)
			}
		})
	}
}

func TestAutomationPolicyNormalizedDefaults(t *testing.T) {
	publicIssuer := newAutomationTestIssuer(t, "public")
	internalIssuer := newAutomationTestIssuer(t, "internal")
	public := &AutomationPolicy{OnDemand: true, Issuers: []certmagic.Issuer{publicIssuer}}
	internal := &AutomationPolicy{OnDemand: true, Issuers: []certmagic.Issuer{internalIssuer}}
	tlsApp := automationTestTLS(t, public, internal)
	tlsApp.Automation.Policies = nil
	tlsApp.Automation.defaultPublicAutomationPolicy = public
	tlsApp.Automation.defaultInternalAutomationPolicy = internal

	for _, tc := range []struct {
		name       string
		wantIssuer certmagic.Issuer
		invalidSNI bool
	}{
		{name: "bücher.example", wantIssuer: publicIssuer},
		{name: "xn--bcher-kva.example", wantIssuer: publicIssuer},
		{name: "*.bücher.example", wantIssuer: publicIssuer},
		{name: "localhost", wantIssuer: internalIssuer},
		{name: "ｌｏｃａｌｈｏｓｔ", wantIssuer: internalIssuer},
		{name: "test.localhost", wantIssuer: internalIssuer},
		{name: "127.0.0.1", wantIssuer: internalIssuer},
		{name: "[::1]", wantIssuer: internalIssuer, invalidSNI: true},
		{name: "", wantIssuer: internalIssuer},
		{name: "bad name", wantIssuer: internalIssuer, invalidSNI: true},
		{name: "xn--example-.com", wantIssuer: publicIssuer, invalidSNI: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tlsApp.getConfigForName(tc.name)
			if len(cfg.Issuers) != 1 || cfg.Issuers[0] != tc.wantIssuer {
				t.Fatalf("incorrect default issuer for %q: %v", tc.name, cfg.Issuers)
			}
			if tc.invalidSNI {
				if _, err := automationTestGetCertificate(cfg, tc.name); err == nil {
					t.Fatal("invalid SNI must not be issued a certificate")
				}
				if publicIssuer.calls != 0 || internalIssuer.calls != 0 {
					t.Fatal("invalid SNI reached an issuer")
				}
			}
		})
	}
	tlsApp.Automation.defaultInternalAutomationPolicy = nil
	if cfg := tlsApp.getConfigForName("localhost"); cfg.Issuers[0] != publicIssuer {
		t.Fatal("missing internal default must still fall back to public policy")
	}
	tlsApp.Automation.Policies = []*AutomationPolicy{internal}
	if cfg := tlsApp.getConfigForName("bücher.example"); cfg.Issuers[0] != internalIssuer {
		t.Fatal("explicit catch-all must take precedence over default policies")
	}
}

func TestAutomationPolicyInvalidSubject(t *testing.T) {
	ap := AutomationPolicy{SubjectsRaw: []string{"xn--example-.com"}}
	if err := ap.Provision(new(TLS)); err == nil {
		t.Fatal("invalid policy A-label must still be rejected during provisioning")
	}
}

func automationTestTLS(t *testing.T, policies ...*AutomationPolicy) *TLS {
	t.Helper()
	tlsApp := &TLS{
		Automation: &AutomationConfig{
			Policies: policies,
			OnDemand: &OnDemandConfig{permission: new(automationTestPermission)},
		},
		logger: zap.NewNop(),
	}
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
			return tlsApp.getConfigForName(cert.Names[0]), nil
		},
		Logger: zap.NewNop(),
	})
	certCacheMu.Lock()
	previousCache := certCache
	certCache = cache
	certCacheMu.Unlock()
	t.Cleanup(func() {
		cache.Stop()
		certCacheMu.Lock()
		certCache = previousCache
		certCacheMu.Unlock()
	})
	storage := &certmagic.FileStorage{Path: t.TempDir()}
	for _, ap := range policies {
		ap.storage = storage
		if err := ap.Provision(tlsApp); err != nil {
			t.Fatal(err)
		}
		ap.magic.OnEvent = nil
		ap.magic.ShouldEmitFunc = func(string) bool { return false }
	}
	return tlsApp
}
