package caddytls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

func TestAutomationPolicyMissingPermission(t *testing.T) {
	var emptyOnDemand AutomationConfig
	if err := json.Unmarshal([]byte(`{"on_demand":{}}`), &emptyOnDemand); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		automation *AutomationConfig
	}{
		{name: "no automation"},
		{name: "no on-demand settings", automation: new(AutomationConfig)},
		{name: "empty JSON on-demand object", automation: &emptyOnDemand},
	} {
		for _, policy := range []struct {
			name string
			ap   AutomationPolicy
		}{
			{name: "explicit subject", ap: AutomationPolicy{OnDemand: true, subjects: []string{"example.com"}}},
			{name: "internal issuer", ap: AutomationPolicy{OnDemand: true, Issuers: []certmagic.Issuer{new(InternalIssuer)}}},
			{name: "tailscale", ap: AutomationPolicy{subjects: []string{"test.example.ts.net"}, Managers: []certmagic.Manager{Tailscale{}}}},
		} {
			t.Run(tc.name+"/"+policy.name, func(t *testing.T) {
				cfg, err := policy.ap.makeCertMagicConfig(&TLS{
					Automation: tc.automation,
					logger:     zap.NewNop(),
				}, policy.ap.Issuers, &certmagic.FileStorage{Path: t.TempDir()})
				if err != nil {
					t.Fatal(err)
				}
				if err := cfg.OnDemand.DecisionFunc(context.Background(), "example.com"); err != nil {
					t.Fatalf("exempted policy without permission module must be allowed: %v", err)
				}
			})
		}
	}
}

func TestAutomationPolicyEmptyPermissionHandshake(t *testing.T) {
	for _, tc := range []struct {
		name    string
		ap      AutomationPolicy
		wantErr bool
	}{
		{name: "explicit subject", ap: AutomationPolicy{OnDemand: true, subjects: []string{"managed.example.com"}}},
		{
			name: "unprotected manager miss",
			ap: AutomationPolicy{
				Managers: []certmagic.Manager{automationTestManager(func(context.Context, *tls.ClientHelloInfo) (*tls.Certificate, error) {
					return nil, nil
				})},
				hadExplicitManagers: true,
			},
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			issuer := newAutomationTestIssuer(t, "test-issuer")
			tc.ap.Issuers = []certmagic.Issuer{issuer}
			cfg := automationTestConfig(t, &tc.ap, &AutomationConfig{OnDemand: new(OnDemandConfig)})
			cert, err := automationTestGetCertificate(cfg, "managed.example.com")
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "no permission module configured") {
					t.Fatalf("expected permission rejection, got %v", err)
				}
				if issuer.calls != 0 {
					t.Fatal("empty permission config must not permit unprotected manager fallback")
				}
			} else if err != nil {
				t.Fatal(err)
			} else if cert == nil || issuer.calls != 1 {
				t.Fatalf("expected local certificate issuance, got certificate %v and %d issuer calls", cert != nil, issuer.calls)
			}
		})
	}
}

func TestAutomationPolicyExternalManagerPermission(t *testing.T) {
	server := httptest.NewTLSServer(nil)
	defer server.Close()
	managerCert := &server.TLS.Certificates[0]

	for _, tc := range []struct {
		name          string
		subjects      []string
		managerHit    bool
		permission    *automationTestPermission
		defaultIssuer bool
		wantCert      bool
		wantIssued    bool
	}{
		{name: "wildcard miss", subjects: []string{"*.example.com"}},
		{name: "catch-all miss"},
		{name: "default issuers miss", defaultIssuer: true},
		{name: "manager success", managerHit: true, wantCert: true},
		{name: "explicit subject miss", subjects: []string{"managed.example.com"}, wantCert: true, wantIssued: true},
		{name: "permission allow", permission: &automationTestPermission{}, wantCert: true, wantIssued: true},
		{name: "permission deny", permission: &automationTestPermission{err: ErrPermissionDenied}},
		{name: "manager success before permission", managerHit: true, permission: &automationTestPermission{err: ErrPermissionDenied}, wantCert: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			issuer := newAutomationTestIssuer(t, "test-issuer")
			managerCalls := 0
			ap := AutomationPolicy{
				subjects: tc.subjects,
				Managers: []certmagic.Manager{automationTestManager(func(context.Context, *tls.ClientHelloInfo) (*tls.Certificate, error) {
					managerCalls++
					if tc.managerHit {
						return managerCert, nil
					}
					return nil, nil
				})},
				hadExplicitManagers: true,
			}
			if !tc.defaultIssuer {
				ap.Issuers = []certmagic.Issuer{issuer}
			}
			var automation *AutomationConfig
			if tc.permission != nil {
				automation = &AutomationConfig{OnDemand: &OnDemandConfig{permission: tc.permission}}
			}
			cfg := automationTestConfig(t, &ap, automation)
			if len(cfg.Issuers) == 0 {
				t.Fatal("issuers must remain configured, even when issuance is forbidden")
			}
			if tc.defaultIssuer {
				// Do not invoke real ACME issuers, even on a broken implementation.
				if err := cfg.OnDemand.DecisionFunc(context.Background(), "managed.example.com"); err == nil {
					t.Fatal("default issuers must be protected after a manager miss")
				}
				return
			}
			cert, err := automationTestGetCertificate(cfg, "managed.example.com")
			if tc.wantCert {
				if err != nil {
					t.Fatalf("getting certificate: %v", err)
				}
				if cert == nil || len(cert.Certificate) == 0 {
					t.Fatal("expected a certificate")
				}
			} else {
				if err == nil {
					t.Fatal("expected certificate to be denied")
				}
				if !strings.Contains(err.Error(), "decision func:") {
					t.Fatalf("expected rejection at permission gate, got %v", err)
				}
			}
			if managerCalls != 1 {
				t.Errorf("expected manager to run once before decision, got %d calls", managerCalls)
			}
			if (issuer.calls > 0) != tc.wantIssued {
				t.Errorf("issuer called %d times, want issuance %v", issuer.calls, tc.wantIssued)
			}
			if tc.permission != nil {
				if tc.managerHit && tc.permission.calls != 0 {
					t.Error("manager success must not require issuance permission")
				} else if !tc.managerHit && tc.permission.calls == 0 {
					t.Error("manager miss must consult configured permission")
				}
			}
		})
	}
}

func TestAutomationPolicyUnprotectedOnDemand(t *testing.T) {
	for _, tc := range []struct {
		name    string
		ap      AutomationPolicy
		wantErr bool
	}{
		{name: "catch-all", ap: AutomationPolicy{OnDemand: true}, wantErr: true},
		{name: "wildcard", ap: AutomationPolicy{OnDemand: true, subjects: []string{"*.example.com"}}, wantErr: true},
		{name: "explicit subject", ap: AutomationPolicy{OnDemand: true, subjects: []string{"example.com"}}},
		{name: "internal issuer", ap: AutomationPolicy{OnDemand: true, Issuers: []certmagic.Issuer{new(InternalIssuer)}}},
		{name: "tailscale", ap: AutomationPolicy{subjects: []string{"test.example.ts.net"}, Managers: []certmagic.Manager{Tailscale{}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := tc.ap.makeCertMagicConfig(&TLS{logger: zap.NewNop()}, tc.ap.Issuers, &certmagic.FileStorage{Path: t.TempDir()})
			if (err != nil) != tc.wantErr {
				t.Fatalf("making config: %v, want error %v", err, tc.wantErr)
			}
			if err == nil {
				if cfg.OnDemand == nil {
					t.Fatal("expected on-demand configuration")
				}
				if err := cfg.OnDemand.DecisionFunc(context.Background(), "example.com"); err != nil {
					t.Fatalf("exempted policy must allow issuance: %v", err)
				}
			}
		})
	}
}

type automationTestManager func(context.Context, *tls.ClientHelloInfo) (*tls.Certificate, error)

func (m automationTestManager) GetCertificate(ctx context.Context, hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return m(ctx, hello)
}

type automationTestPermission struct {
	err   error
	calls int
}

func (p *automationTestPermission) CertificateAllowed(context.Context, string) error {
	p.calls++
	return p.err
}

type automationTestIssuer struct {
	key   *ecdsa.PrivateKey
	root  *x509.Certificate
	calls int
}

func newAutomationTestIssuer(t *testing.T, name string) *automationTestIssuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, root, root, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &automationTestIssuer{key: key, root: root}
}

func (iss *automationTestIssuer) IssuerKey() string { return iss.root.Subject.CommonName }

func (iss *automationTestIssuer) Issue(_ context.Context, csr *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	iss.calls++
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(int64(iss.calls + 1)),
		DNSNames:     csr.DNSNames,
		IPAddresses:  csr.IPAddresses,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(12 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, iss.root, csr.PublicKey, iss.key)
	if err != nil {
		return nil, err
	}
	bundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: iss.root.Raw})...)
	return &certmagic.IssuedCertificate{Certificate: bundle}, nil
}

func automationTestConfig(t *testing.T, ap *AutomationPolicy, automation *AutomationConfig) *certmagic.Config {
	t.Helper()
	cfg, err := ap.makeCertMagicConfig(&TLS{
		Automation: automation,
		logger:     zap.NewNop(),
	}, ap.Issuers, &certmagic.FileStorage{Path: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	// These tests exercise CertMagic's manager/permission/issuer pipeline without the events app.
	cfg.OnEvent = nil
	cfg.ShouldEmitFunc = func(string) bool { return false }
	var magic *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return magic, nil },
		Logger:           zap.NewNop(),
	})
	t.Cleanup(cache.Stop)
	magic = certmagic.New(cache, cfg)
	return magic
}

func automationTestGetCertificate(cfg *certmagic.Config, name string) (*tls.Certificate, error) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	return cfg.GetCertificateWithContext(context.Background(), &tls.ClientHelloInfo{
		ServerName: name,
		Conn:       server,
	})
}

func TestAutomationPolicyMakeCertMagicConfigImplicitTailscaleManagersOnly(t *testing.T) {
	ap := AutomationPolicy{
		Managers: []certmagic.Manager{Tailscale{}},
		subjects: []string{"test-node.example.ts.net"},
	}

	cfg, err := ap.makeCertMagicConfig(&TLS{
		logger: zap.NewNop(),
	}, nil, &certmagic.FileStorage{Path: t.TempDir()})
	if err != nil {
		t.Fatalf("making certmagic config: %v", err)
	}
	if cfg.OnDemand == nil {
		t.Fatal("expected on-demand config to be set")
	}
	if len(cfg.Issuers) != 0 {
		t.Fatalf("expected no issuers for tailscale-managed ts.net policy, got %d", len(cfg.Issuers))
	}
}

func TestAutomationPolicyImplicitTailscaleManagersOnlyCatchAll(t *testing.T) {
	ap := AutomationPolicy{
		Managers: []certmagic.Manager{Tailscale{}},
	}
	if ap.implicitTailscaleManagersOnly() {
		t.Fatal("expected catch-all manager policy to remain outside tailscale-only special case")
	}
}
