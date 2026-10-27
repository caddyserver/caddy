package caddytls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

func noopGetConfig(certmagic.Certificate) (*certmagic.Config, error) {
	return nil, nil
}

// withCleanCertCacheState isolates a test from the package-level certificate
// cache state, restoring it (and stopping any cache the test published) when
// the test ends.
func withCleanCertCacheState(t *testing.T) {
	t.Helper()
	certCacheMu.Lock()
	origCache, origOpts, origApp := certCache, certCacheOpts, certCacheApp
	certCache, certCacheOpts, certCacheApp = nil, certmagic.CacheOptions{}, nil
	certCacheMu.Unlock()
	t.Cleanup(func() {
		certCacheMu.Lock()
		published := certCache
		certCache, certCacheOpts, certCacheApp = origCache, origOpts, origApp
		certCacheMu.Unlock()
		if published != nil && published != origCache {
			published.Stop()
		}
	})
}

// provisionAndPublish mimics what a TLS app does across Provision and Start:
// resolve the cache it will use, then publish it once provisioning succeeded.
func provisionAndPublish(opts certmagic.CacheOptions) *TLS {
	app := new(TLS)
	app.provisionCertCache(opts)
	app.publishCertCache()
	return app
}

func baseOpts() certmagic.CacheOptions {
	return normalizeCacheOptions(certmagic.CacheOptions{
		GetConfigForCert:   noopGetConfig,
		RenewCheckInterval: 1 * time.Hour,
		OCSPCheckInterval:  1 * time.Hour,
		Capacity:           100,
	})
}

// A reload that does not change any of the options fixed at cache creation
// must keep using the published cache.
func TestProvisionCertCacheReusesPublishedCache(t *testing.T) {
	withCleanCertCacheState(t)

	opts := baseOpts()
	first := provisionAndPublish(opts)
	if first.cache == nil {
		t.Fatal("first provision did not create a cache")
	}

	next := new(TLS)
	next.provisionCertCache(opts)
	if next.cache != first.cache {
		t.Fatal("unchanged options did not reuse the published cache")
	}
}

// certmagic defaults an unset interval, so a config that spells out
// certmagic's own default is equivalent to one that leaves it unset and must
// not force a cache replacement.
func TestProvisionCertCacheIgnoresExplicitlyDefaultedIntervals(t *testing.T) {
	withCleanCertCacheState(t)

	unset := normalizeCacheOptions(certmagic.CacheOptions{
		GetConfigForCert: noopGetConfig,
		Capacity:         100,
	})
	first := provisionAndPublish(unset)

	explicit := normalizeCacheOptions(certmagic.CacheOptions{
		GetConfigForCert:   noopGetConfig,
		RenewCheckInterval: certmagic.DefaultRenewCheckInterval,
		OCSPCheckInterval:  certmagic.DefaultOCSPCheckInterval,
		Capacity:           100,
	})
	next := new(TLS)
	next.provisionCertCache(explicit)
	if next.cache != first.cache {
		t.Fatal("explicitly-defaulted intervals replaced the cache")
	}
}

// The heart of the fix: resolving the cache for a new config must not touch
// the published cache at all. The config may still fail to provision or
// start, in which case the previous config keeps running and must keep a
// live, maintained cache.
func TestProvisionCertCacheLeavesPublishedCacheRunning(t *testing.T) {
	withCleanCertCacheState(t)

	published := provisionAndPublish(baseOpts())

	changed := baseOpts()
	changed.RenewCheckInterval = 2 * time.Hour
	next := new(TLS)
	next.provisionCertCache(changed)
	replacement := next.cache

	if replacement == published.cache {
		t.Fatal("changed options did not produce a new cache")
	}

	// nothing is published until Start
	certCacheMu.RLock()
	stillPublished, stillOpts, stillApp := certCache, certCacheOpts, certCacheApp
	certCacheMu.RUnlock()
	if stillPublished != published.cache {
		t.Fatal("provisioning published the replacement cache")
	}
	if stillOpts.RenewCheckInterval != 1*time.Hour {
		t.Fatal("provisioning overwrote the published cache's recorded options")
	}
	if stillApp != published {
		t.Fatal("provisioning reassigned the published cache's app")
	}

	// the replacement is private to the provisioning config, so the test
	// owns it; stop it the way a failed config's Cleanup would
	replacement.Stop()

	// Cache.Stop closes a channel, so stopping an already-stopped cache
	// panics. That this succeeds proves provisioning left the published
	// cache's maintenance running.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("published cache had already been stopped during provisioning: %v", r)
		}
	}()
	published.cache.Stop()
	certCacheMu.Lock()
	certCache = nil
	certCacheMu.Unlock()
}

// Start is what makes a provisioned cache the one the committed config
// serves from.
func TestPublishCertCacheAfterSuccessfulProvision(t *testing.T) {
	withCleanCertCacheState(t)

	published := provisionAndPublish(baseOpts())

	changed := baseOpts()
	changed.Capacity = 200
	next := new(TLS)
	next.provisionCertCache(changed)
	next.publishCertCache()

	certCacheMu.RLock()
	gotCache, gotOpts, gotApp := certCache, certCacheOpts, certCacheApp
	certCacheMu.RUnlock()
	if gotCache != next.cache {
		t.Fatal("Start did not publish the new cache")
	}
	if gotOpts.Capacity != 200 {
		t.Fatal("Start did not record the new cache's options")
	}
	if gotApp != next {
		t.Fatal("Start did not publish the new app")
	}

	// the superseded cache is the outgoing app's to stop, as Cleanup does
	published.cache.Stop()
}

// A cache reused across reloads keeps the GetConfigForCert callback built by
// the app that created it, so maintenance on it has to resolve to whichever
// app currently owns the cache rather than to its creator. A cache that is
// not published is only populated by its creator.
func TestAppForCacheFollowsCacheOwner(t *testing.T) {
	withCleanCertCacheState(t)

	opts := baseOpts()
	first := provisionAndPublish(opts)
	if got := first.appForCache(); got != first {
		t.Fatal("publishing app did not resolve to itself")
	}

	// a reload reusing the same cache: until it publishes, the committed
	// app still owns the cache
	second := new(TLS)
	second.provisionCertCache(opts)
	if second.cache != first.cache {
		t.Fatal("expected the reload to reuse the cache")
	}
	if got := second.appForCache(); got != first {
		t.Fatal("unpublished reload took ownership of the shared cache early")
	}
	second.publishCertCache()
	if got := second.appForCache(); got != second {
		t.Fatal("published reload did not take ownership of the shared cache")
	}

	// a reload that replaces the cache owns its own cache immediately,
	// since nothing else ever reads it
	changed := opts
	changed.Capacity = 500
	third := new(TLS)
	third.provisionCertCache(changed)
	if got := third.appForCache(); got != third {
		t.Fatal("app provisioning a private cache did not own it")
	}
	third.cache.Stop()
}

// selfSignedCert returns a short-lived self-signed certificate for san.
func selfSignedCert(t *testing.T, san string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: san},
		DNSNames:     []string{san},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// cacheUnmanagedCert puts cert into app's cache the way a manually-loaded
// certificate reaches it. Storage is a temporary directory and OCSP stapling
// is off, so this touches neither the real storage nor the network.
func cacheUnmanagedCert(t *testing.T, app *TLS, cert tls.Certificate) {
	t.Helper()
	cfg := certmagic.New(app.cache, certmagic.Config{
		Storage: &certmagic.FileStorage{Path: t.TempDir()},
		OCSP:    certmagic.OCSPConfig{DisableStapling: true},
		Logger:  zap.NewNop(),
	})
	if _, err := cfg.CacheUnmanagedTLSCertificate(context.Background(), cert, nil); err != nil {
		t.Fatalf("caching unmanaged certificate: %v", err)
	}
}

// An option-changing reload publishes a replacement cache, and anything the
// outgoing config provisioned has to keep resolving certificates in the cache
// its own config populated. A reverse-proxy transport is the case that matters:
// its GetClientCertificate closure goes on serving requests while the outgoing
// config drains, and the replacement cache is loaded from scratch by the
// incoming config, so a lookup that follows the publication finds nothing and
// fails a client-certificate handshake that was working a moment earlier.
//
// That is why the lookup is a method on the app rather than the package-level
// AllMatchingCertificates, which reads whichever cache is published now.
func TestAppCacheLookupSurvivesOptionChangingReload(t *testing.T) {
	withCleanCertCacheState(t)

	const san = "client.example.com"

	outgoing := provisionAndPublish(baseOpts())
	cacheUnmanagedCert(t, outgoing, selfSignedCert(t, san))

	outgoingStopped := false
	t.Cleanup(func() {
		if !outgoingStopped {
			outgoing.cache.Stop()
		}
	})

	if got := len(outgoing.AllMatchingCertificates(san)); got != 1 {
		t.Fatalf("outgoing config holds %d certificates for %s, want 1", got, san)
	}

	// a reload changing an option fixed at cache creation, so the cache is
	// replaced rather than reused
	changed := baseOpts()
	changed.Capacity++
	incoming := new(TLS)
	incoming.provisionCertCache(changed)
	if incoming.cache == outgoing.cache {
		t.Fatal("expected a capacity change to replace the cache")
	}
	incoming.publishCertCache()

	// the published cache is now the incoming config's, which never loaded
	// this certificate — this is exactly what the package-level lookup sees
	if got := len(AllMatchingCertificates(san)); got != 0 {
		t.Fatalf("replacement cache holds %d certificates for %s, want 0", got, san)
	}

	// an in-flight consumer of the outgoing config still finds it
	if got := len(outgoing.AllMatchingCertificates(san)); got != 1 {
		t.Errorf("outgoing config lost its certificate when the reload published: got %d, want 1", got)
	}

	// and still finds it after that cache has been stopped, which is what the
	// outgoing app's Cleanup does once the new config is committed; stopping a
	// certmagic cache ends its maintenance goroutine and leaves its contents
	// readable, so a draining transport is covered for its whole lifetime
	outgoing.cache.Stop()
	outgoingStopped = true
	if got := len(outgoing.AllMatchingCertificates(san)); got != 1 {
		t.Errorf("stopped cache served %d certificates, want 1", got)
	}
}
