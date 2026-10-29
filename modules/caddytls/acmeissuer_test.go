package caddytls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	_ "github.com/caddyserver/caddy/v2/modules/internal/network"
	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v3/acme"
	"go.uber.org/zap"
)

func TestACMEIssuerExpandPlaceholders(t *testing.T) {
	t.Setenv("CADDY_TEST_CA_URL", "https://acme.example.com/directory")
	t.Setenv("CADDY_TEST_TEST_CA_URL", "https://acme2.example.com/directory")
	t.Setenv("CADDY_TEST_EAB_KEY_ID", "example-key-id")
	t.Setenv("CADDY_TEST_EAB_MAC_KEY", "example-mac-key")

	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	defer cancel()

	iss := &ACMEIssuer{
		CA:     "{env.CADDY_TEST_CA_URL}",
		TestCA: "{env.CADDY_TEST_TEST_CA_URL}",
		ExternalAccount: &acme.EAB{
			KeyID:  "{env.CADDY_TEST_EAB_KEY_ID}",
			MACKey: "{env.CADDY_TEST_EAB_MAC_KEY}",
		},
	}

	if err := iss.Provision(caddyCtx); err != nil {
		t.Fatalf("Provision() returned unexpected error: %v", err)
	}

	if want := "https://acme.example.com/directory"; iss.CA != want {
		t.Errorf("CA: got %q, want %q", iss.CA, want)
	}
	if want := "https://acme2.example.com/directory"; iss.TestCA != want {
		t.Errorf("TestCA: got %q, want %q", iss.TestCA, want)
	}
	if want := "example-key-id"; iss.ExternalAccount.KeyID != want {
		t.Errorf("ExternalAccount.KeyID: got %q, want %q", iss.ExternalAccount.KeyID, want)
	}
	if want := "example-mac-key"; iss.ExternalAccount.MACKey != want {
		t.Errorf("ExternalAccount.MACKey: got %q, want %q", iss.ExternalAccount.MACKey, want)
	}
}

// The HTTP app provisions ACME issuers again to fill in its ports and then
// rebuilds the CertMagic config; requests must still use the configured proxy (#8283).
func TestACMEIssuerNetworkProxyAfterRebuildCertMagic(t *testing.T) {
	var proxied atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect && r.Host == "acme.invalid:443" {
			proxied.Add(1)
		}
		http.Error(w, "test proxy", http.StatusBadGateway)
	}))
	defer proxy.Close()

	certCacheMu.Lock()
	prevCache := certCache
	certCache = certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return nil, nil },
	})
	certCacheMu.Unlock()
	defer func() {
		certCacheMu.Lock()
		certCache.Stop()
		certCache = prevCache
		certCacheMu.Unlock()
	}()

	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	defer cancel()
	tlsApp := &TLS{ctx: caddyCtx, logger: zap.NewNop()}

	iss := &ACMEIssuer{
		CA:              "https://acme.invalid/directory",
		NetworkProxyRaw: []byte(`{"from":"url","url":"` + proxy.URL + `"}`),
	}
	if err := iss.Provision(caddyCtx); err != nil {
		t.Fatalf("provisioning issuer: %v", err)
	}
	ap := &AutomationPolicy{
		Issuers: []certmagic.Issuer{iss},
		storage: &certmagic.FileStorage{Path: t.TempDir()},
	}
	if err := ap.Provision(tlsApp); err != nil {
		t.Fatalf("provisioning automation policy: %v", err)
	}

	// what the HTTP app's fillInACMEIssuer and createAutomationPolicies do
	if err := iss.Provision(caddyCtx); err != nil {
		t.Fatalf("re-provisioning issuer: %v", err)
	}
	if err := ap.RebuildCertMagic(tlsApp); err != nil {
		t.Fatalf("rebuilding certmagic config: %v", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"example.com"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancelIssue := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancelIssue()
	if _, err := iss.Issue(ctx, csr); err == nil {
		t.Fatal("expected issuance to fail against the test proxy")
	}
	if proxied.Load() == 0 {
		t.Error("ACME request did not go through the configured network proxy")
	}
}

func TestACMEIssuerUnmarshalCaddyfileNetworkProxy(t *testing.T) {
	for i, tc := range []struct {
		name    string
		input   string
		wantRaw string
		wantErr bool
	}{
		{
			name:    "url",
			input:   "acme {\n\tnetwork_proxy url http://localhost:8080\n}",
			wantRaw: `{"from":"url","url":"http://localhost:8080"}`,
		},
		{
			name:    "url with placeholder",
			input:   "acme {\n\tnetwork_proxy url {env.ACME_PROXY}\n}",
			wantRaw: `{"from":"url","url":"{env.ACME_PROXY}"}`,
		},
		{
			name:    "none",
			input:   "acme {\n\tnetwork_proxy none\n}",
			wantRaw: `{"from":"none"}`,
		},
		{
			name:  "not set",
			input: "acme {\n\temail admin@example.com\n}",
		},
		{
			name:    "missing module name",
			input:   "acme {\n\tnetwork_proxy\n}",
			wantErr: true,
		},
		{
			name:    "unknown module name",
			input:   "acme {\n\tnetwork_proxy bogus\n}",
			wantErr: true,
		},
	} {
		var iss ACMEIssuer
		err := iss.UnmarshalCaddyfile(caddyfile.NewTestDispenser(tc.input))
		if tc.wantErr {
			if err == nil {
				t.Errorf("Test %d (%s): expected error but got none", i, tc.name)
			}
			continue
		}
		if err != nil {
			t.Errorf("Test %d (%s): unexpected error: %v", i, tc.name, err)
			continue
		}
		if got := string(iss.NetworkProxyRaw); got != tc.wantRaw {
			t.Errorf("Test %d (%s): NetworkProxyRaw = %q, want %q", i, tc.name, got, tc.wantRaw)
		}
	}
}
