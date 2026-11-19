package caddytls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"

	"github.com/caddyserver/caddy/v2"
)

type testIssuer struct{}

func (testIssuer) IssuerKey() string { return "test" }

func (testIssuer) Issue(context.Context, *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	return nil, errors.New("not implemented")
}

// TestProvisionDoesNotReplaceCacheCallback ensures that cache maintenance keeps
// using the running TLS app while a new one is provisioned, and only switches
// to the new app once it is started.
func TestProvisionDoesNotReplaceCacheCallback(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	certCacheMu.Lock()
	origCache := certCache
	certCacheMu.Unlock()
	t.Cleanup(func() {
		certCacheMu.Lock()
		certCache = origCache
		certCacheMu.Unlock()
	})

	// cache owned by the "running" app, holding one managed certificate
	oldCalls := 0
	errOldApp := errors.New("old app")
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
			oldCalls++
			return nil, errOldApp
		},
	})
	defer cache.Stop()
	certCacheMu.Lock()
	certCache = cache
	certCacheMu.Unlock()

	storage := &certmagic.FileStorage{Path: t.TempDir()}
	storeTestCert(t, storage, "test", "example.com")
	cfg := certmagic.New(cache, certmagic.Config{
		Storage: storage,
		Issuers: []certmagic.Issuer{testIssuer{}},
		OCSP:    certmagic.OCSPConfig{DisableStapling: true},
	})
	if _, err := cfg.CacheManagedCertificate(t.Context(), "example.com"); err != nil {
		t.Fatalf("caching managed certificate: %v", err)
	}

	// provision (but do not start) a new TLS app
	ctx, err := caddy.ProvisionContext(&caddy.Config{})
	if err != nil {
		t.Fatal(err)
	}
	app := &TLS{DisableStorageClean: true}
	if err := app.Provision(ctx); err != nil {
		t.Fatalf("provisioning: %v", err)
	}

	_ = cache.RenewManagedCertificates(t.Context())
	if oldCalls != 1 {
		t.Fatalf("expected the running app's callback to be used once, got %d calls", oldCalls)
	}

	// once started, the new app takes over
	if err := app.Start(); err != nil {
		t.Fatalf("starting: %v", err)
	}
	defer app.Stop()

	_ = cache.RenewManagedCertificates(t.Context())
	if oldCalls != 1 {
		t.Fatalf("expected the started app's callback to be used, but the old one was called again")
	}
}

func storeTestCert(t *testing.T, storage certmagic.Storage, issuerKey, name string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	for k, v := range map[string][]byte{
		certmagic.StorageKeys.SiteCert(issuerKey, name):       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		certmagic.StorageKeys.SitePrivateKey(issuerKey, name): pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		certmagic.StorageKeys.SiteMeta(issuerKey, name):       []byte(`{}`),
	} {
		if err := storage.Store(ctx, k, v); err != nil {
			t.Fatal(err)
		}
	}
}
