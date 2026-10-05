package caddytls

import (
	"fmt"
	"testing"

	"github.com/caddyserver/certmagic"

	"github.com/caddyserver/caddy/v2"
	_ "github.com/caddyserver/caddy/v2/modules/filestorage"
)

// failingCertLoader is a test-only certificate loader that always fails, so a
// config can be made to fail provisioning at a point *after* the TLS app has
// resolved the certificate cache it intends to use.
type failingCertLoader struct{}

func (failingCertLoader) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.certificates.failing_test",
		New: func() caddy.Module { return failingCertLoader{} },
	}
}

func (failingCertLoader) LoadCertificates() ([]Certificate, error) {
	return nil, fmt.Errorf("deliberate failure from the test certificate loader")
}

func init() { caddy.RegisterModule(failingCertLoader{}) }

func tlsConfigJSON(storageRoot string, capacity int, fail bool) []byte {
	certs := ""
	if fail {
		certs = `"certificates": {"failing_test": {}},`
	}
	return []byte(fmt.Sprintf(`{
		"admin": {"disabled": true},
		"storage": {"module": "file_system", "root": %q},
		"apps": {
			"tls": {
				%s
				"disable_storage_clean": true,
				"cache": {"capacity": %d}
			}
		}
	}`, storageRoot, certs, capacity))
}

func activeTLSApp(t *testing.T) *TLS {
	t.Helper()
	app, err := caddy.ActiveContext().AppIfConfigured("tls")
	if err != nil || app == nil {
		t.Fatalf("no active tls app: %v", err)
	}
	return app.(*TLS)
}

// stopCaddyAndCertCache tears the running config down and returns the
// package-level cache state to zero, so the next test does not inherit a
// published cache. consumed names a cache the test stopped itself, which must
// not be stopped twice.
func stopCaddyAndCertCache(consumed **certmagic.Cache) func() {
	return func() {
		caddy.Stop()
		certCacheMu.Lock()
		published := certCache
		certCache, certCacheOpts, certCacheApp = nil, certmagic.CacheOptions{}, nil
		certCacheMu.Unlock()
		if published != nil && published != *consumed {
			published.Stop()
		}
	}
}

// assertCacheRunning fails the test if c's maintenance goroutine has already
// been stopped. Cache.Stop closes a channel and waits for the goroutine to
// exit, so stopping an already-stopped cache panics on a closed channel;
// completing without a panic is therefore proof the cache was still being
// maintained. This consumes c: it is stopped either way.
func assertCacheRunning(t *testing.T, c *certmagic.Cache) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("certificate cache was no longer being maintained: %v", r)
		}
	}()
	c.Stop()
}

// A reload that changes the cache options and then fails to provision must
// leave the running config's cache alone: still published, still maintained.
// Before this change the replacement cache was published and the running
// config's cache was stopped during provisioning, so a later failure left the
// active config without certificate maintenance.
func TestFailedReloadLeavesRunningCacheIntact(t *testing.T) {
	storage := t.TempDir()
	if err := caddy.Load(tlsConfigJSON(storage, 100, false), true); err != nil {
		t.Fatalf("loading initial config: %v", err)
	}
	var consumed *certmagic.Cache
	t.Cleanup(stopCaddyAndCertCache(&consumed))

	running := activeTLSApp(t)
	certCacheMu.RLock()
	cacheBefore, optsBefore, appBefore := certCache, certCacheOpts, certCacheApp
	certCacheMu.RUnlock()
	if cacheBefore == nil || cacheBefore != running.cache {
		t.Fatal("initial config did not publish its cache")
	}

	// a reload that changes the cache capacity (forcing a replacement) and
	// then fails while loading certificates
	err := caddy.Load(tlsConfigJSON(storage, 200, true), true)
	if err == nil {
		t.Fatal("expected the reload to fail")
	}

	// the old config must still be the active one, unchanged
	if got := activeTLSApp(t); got != running {
		t.Fatal("failed reload replaced the active app")
	}
	certCacheMu.RLock()
	cacheAfter, optsAfter, appAfter := certCache, certCacheOpts, certCacheApp
	certCacheMu.RUnlock()
	if cacheAfter != cacheBefore {
		t.Fatal("failed reload replaced the published cache")
	}
	if optsAfter.Capacity != optsBefore.Capacity {
		t.Fatalf("failed reload changed the published cache options: %d -> %d",
			optsBefore.Capacity, optsAfter.Capacity)
	}
	if appAfter != appBefore {
		t.Fatal("failed reload reassigned the published cache's app")
	}

	// The decisive check: the running config's cache must still be having its
	// certificates renewed and its OCSP staples refreshed. Every other symptom
	// of the old behaviour is repaired by the failed app's Cleanup; a cache
	// whose maintenance was stopped mid-reload is not.
	consumed = cacheBefore
	assertCacheRunning(t, cacheBefore)
}

// A reload that changes the cache options and succeeds must publish the new
// cache and retire the old one.
func TestSuccessfulReloadReplacesCache(t *testing.T) {
	storage := t.TempDir()
	if err := caddy.Load(tlsConfigJSON(storage, 100, false), true); err != nil {
		t.Fatalf("loading initial config: %v", err)
	}
	var consumed *certmagic.Cache
	t.Cleanup(stopCaddyAndCertCache(&consumed))

	first := activeTLSApp(t)
	firstCache := first.cache

	if err := caddy.Load(tlsConfigJSON(storage, 200, false), true); err != nil {
		t.Fatalf("reloading with a changed capacity: %v", err)
	}

	second := activeTLSApp(t)
	if second == first {
		t.Fatal("reload did not install a new app")
	}
	if second.cache == firstCache {
		t.Fatal("changed cache options did not replace the cache")
	}
	certCacheMu.RLock()
	published, opts := certCache, certCacheOpts
	certCacheMu.RUnlock()
	if published != second.cache {
		t.Fatal("reload did not publish the new cache")
	}
	if opts.Capacity != 200 {
		t.Fatalf("published options not updated: capacity %d", opts.Capacity)
	}
}

// A reload that leaves the cache options alone must keep the very same cache,
// so certificates already loaded are not thrown away.
func TestReloadWithUnchangedOptionsKeepsCache(t *testing.T) {
	storage := t.TempDir()
	if err := caddy.Load(tlsConfigJSON(storage, 100, false), true); err != nil {
		t.Fatalf("loading initial config: %v", err)
	}
	var consumed *certmagic.Cache
	t.Cleanup(stopCaddyAndCertCache(&consumed))

	firstCache := activeTLSApp(t).cache

	if err := caddy.Load(tlsConfigJSON(storage, 100, false), true); err != nil {
		t.Fatalf("reloading with identical cache options: %v", err)
	}

	second := activeTLSApp(t)
	if second.cache != firstCache {
		t.Fatal("reload with unchanged options replaced the cache")
	}
	// the surviving cache must be owned by the new app, so maintenance
	// consults the current config
	if got := second.appForCache(); got != second {
		t.Fatal("reused cache was not handed to the new app")
	}
}
