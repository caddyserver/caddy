package caddytls

import (
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
)

// The certificate cache's options are immutable once it is created (its
// maintenance tickers are started with them), so a provision with changed
// options must REPLACE the cache rather than mutate a live one, and a
// provision with identical options must reuse it.
func TestProvisionCertCacheReplacesOnOptionChange(t *testing.T) {
	certCacheMu.Lock()
	origCache, origOpts, origApp := certCache, certCacheOpts, certCacheApp
	certCache = nil
	certCacheMu.Unlock()
	defer func() {
		certCacheMu.Lock()
		if certCache != nil && certCache != origCache {
			certCache.Stop()
		}
		certCache, certCacheOpts, certCacheApp = origCache, origOpts, origApp
		certCacheMu.Unlock()
	}()

	app := new(TLS)
	getCfg := func(certmagic.Certificate) (*certmagic.Config, error) {
		return nil, nil
	}
	optsA := certmagic.CacheOptions{
		GetConfigForCert:   getCfg,
		RenewCheckInterval: 1 * time.Hour,
		OCSPCheckInterval:  1 * time.Hour,
		Capacity:           100,
	}

	if old := provisionCertCache(app, optsA); old != nil {
		t.Fatal("first provision returned a cache to stop")
	}
	certCacheMu.RLock()
	first := certCache
	certCacheMu.RUnlock()
	if first == nil {
		t.Fatal("first provision did not create the cache")
	}

	// identical options: cache is reused, nothing to stop
	if old := provisionCertCache(app, optsA); old != nil {
		t.Fatal("unchanged options returned a cache to stop")
	}
	certCacheMu.RLock()
	same := certCache
	certCacheMu.RUnlock()
	if same != first {
		t.Fatal("unchanged options replaced the cache")
	}

	// changed interval: cache is replaced and the old one handed back
	optsB := optsA
	optsB.RenewCheckInterval = 2 * time.Hour
	old := provisionCertCache(app, optsB)
	if old != first {
		t.Fatal("changed options did not hand back the previous cache")
	}
	old.Stop()
	certCacheMu.RLock()
	replaced := certCache
	gotOpts := certCacheOpts
	certCacheMu.RUnlock()
	if replaced == first {
		t.Fatal("changed options did not replace the cache")
	}
	if gotOpts.RenewCheckInterval != 2*time.Hour {
		t.Fatal("recorded options were not updated")
	}
}
