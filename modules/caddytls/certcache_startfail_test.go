package caddytls

import (
	"fmt"
	"testing"

	"github.com/caddyserver/caddy/v2"
	_ "github.com/caddyserver/caddy/v2/modules/filestorage"
)

// Apps are started by ranging over a map, so whether the TLS app starts before
// failingApp is not deterministic. These two variables let a test detect the
// iteration it cares about: the one where TLS started — and therefore published
// its cache — before the config failed. Only written from the start of a
// caddy.Load on the test's own goroutine.
var (
	// the app serving the config that was running before the load
	appBeforeLoad *TLS
	// whether a different app had published its cache by the time failingApp
	// aborted the load
	publishedBeforeFailure bool
)

// failingApp is a test-only app that always fails to start, so a config can be
// made to fail *after* the TLS app has started and published its cache.
type failingApp struct{}

func (failingApp) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "failing_test_app",
		New: func() caddy.Module { return new(failingApp) },
	}
}

func (failingApp) Start() error {
	certCacheMu.RLock()
	publisher := certCacheApp
	certCacheMu.RUnlock()
	publishedBeforeFailure = publisher != nil && publisher != appBeforeLoad
	return fmt.Errorf("deliberate failure from the test app")
}

func (failingApp) Stop() error { return nil }

func init() { caddy.RegisterModule(failingApp{}) }

func failingAppConfigJSON(storageRoot string, capacity int) []byte {
	return []byte(fmt.Sprintf(`{
		"admin": {"disabled": true},
		"storage": {"module": "file_system", "root": %q},
		"apps": {
			"tls": {
				"disable_storage_clean": true,
				"cache": {"capacity": %d}
			},
			"failing_test_app": {}
		}
	}`, storageRoot, capacity))
}

// A config can fail *after* the TLS app has started, either because another app
// fails to start or because finishSettingUp fails; both reach the deferred
// cancelFunc in run(), so Cleanup runs for the app that already published its
// cache. The running config must come through that untouched too: still the
// active app, still the published cache, still maintained.
func TestCacheSurvivesFailureAfterTLSStarted(t *testing.T) {
	storage := t.TempDir()
	if err := caddy.Load(tlsConfigJSON(storage, 100, false), true); err != nil {
		t.Fatalf("loading initial config: %v", err)
	}
	t.Cleanup(stopCaddyAndCertCache())

	running := activeTLSApp(t)
	certCacheMu.RLock()
	cacheBefore, optsBefore := certCache, certCacheOpts
	certCacheMu.RUnlock()
	if cacheBefore == nil || cacheBefore != running.cache {
		t.Fatal("initial config did not publish its cache")
	}
	appBeforeLoad = running

	// Retry until the app start order puts TLS first, which is the case this
	// test is about. The assertions hold on every iteration regardless of
	// order; only the exercised code path differs.
	const attempts = 50
	exercised := false
	for i := 0; i < attempts && !exercised; i++ {
		publishedBeforeFailure = false

		err := caddy.Load(failingAppConfigJSON(storage, 200), true)
		if err == nil {
			t.Fatal("expected the load to fail")
		}
		exercised = publishedBeforeFailure

		if got := activeTLSApp(t); got != running {
			t.Fatalf("attempt %d: failed load replaced the active app", i)
		}
		certCacheMu.RLock()
		cacheAfter, optsAfter, appAfter := certCache, certCacheOpts, certCacheApp
		certCacheMu.RUnlock()
		if cacheAfter != cacheBefore {
			t.Fatalf("attempt %d: published cache was not restored to the running config's", i)
		}
		if optsAfter.Capacity != optsBefore.Capacity {
			t.Fatalf("attempt %d: published cache options left at the failed config's: %d -> %d",
				i, optsBefore.Capacity, optsAfter.Capacity)
		}
		if appAfter != running {
			t.Fatalf("attempt %d: published cache's app was not restored to the running one", i)
		}
	}
	if !exercised {
		t.Fatalf("in %d attempts the TLS app never started before the failing app, so the "+
			"publish-then-fail path was never exercised", attempts)
	}

	// the running config's cache must still be maintained
	assertCacheRunning(t, cacheBefore)
}
