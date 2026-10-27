package caddytls

import (
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// newObservedApp returns a TLS app whose logger records everything at or above
// lvl into the returned sink, standing in for one config's logging setup.
func newObservedApp(lvl zapcore.Level) (*TLS, *observer.ObservedLogs) {
	core, logs := observer.New(lvl)
	return &TLS{logger: zap.New(core)}, logs
}

// A cache reused across a reload must log through the config that currently
// owns it, not the one that created it.
//
// certmagic captures a cache's logger in NewCache and never replaces it:
// SetOptions writes only Cache.options, leaving the Cache.logger field that
// every cache and maintenance log statement uses alone, and the maintenance
// goroutine derives its own logger from it once at startup. So without the
// indirection in cacheLogger, a reused cache keeps writing certificate renewal
// and OCSP failures to the outgoing config's destination — which that config's
// cleanup may already have closed — and ignores the reload entirely.
func TestCacheLoggerFollowsCacheOwnerAcrossReload(t *testing.T) {
	withCleanCertCacheState(t)

	first, firstLogs := newObservedApp(zapcore.DebugLevel)
	firstOpts := baseOpts()
	firstOpts.Logger = first.cacheLogger()
	first.provisionCertCache(firstOpts)
	first.publishCertCache()

	// the one logger value certmagic has for this cache, for as long as the
	// cache lives; everything below logs through it, because the cache has
	// nothing else
	captured := firstOpts.Logger
	maintenance := captured.Named("maintenance") // as certmagic's maintainAssets does

	// assertions filter on the messages this test emits, because the caches
	// created above are real: their maintenance goroutines log through the
	// same delegating logger, and when those entries land in the observed
	// sinks is scheduling-dependent
	maintenance.Error("renewing certificate")
	renewals := firstLogs.FilterMessage("renewing certificate")
	if got := renewals.Len(); got != 1 {
		t.Fatalf("creating config received %d cache logs, want 1", got)
	}
	if name := renewals.All()[0].LoggerName; name != "tls.cache.maintenance" {
		t.Errorf("cache log went out as %q, want tls.cache.maintenance", name)
	}

	// reload without changing any option fixed at cache creation, so the cache
	// is reused and certmagic keeps the logger captured above
	second, secondLogs := newObservedApp(zapcore.DebugLevel)
	secondOpts := baseOpts()
	secondOpts.Logger = second.cacheLogger()
	second.provisionCertCache(secondOpts)
	if second.cache != first.cache {
		t.Fatal("expected the reload to reuse the published cache")
	}
	second.publishCertCache()

	maintenance.Error("renewing certificate")
	if got := secondLogs.FilterMessage("renewing certificate").Len(); got != 1 {
		t.Errorf("reloaded config received %d cache logs, want 1", got)
	}
	if got := firstLogs.FilterMessage("renewing certificate").Len(); got != 1 {
		t.Errorf("outgoing config kept receiving cache logs after the reload: %d total, want the 1 from before it", got)
	}

	// certmagic also derives field-carrying loggers from the cache's logger
	// (updateARI does), so With has to carry its fields to the delegate
	captured.With(zap.String("identifier", "example.com")).Error("updating renewal info")
	updates := secondLogs.FilterMessage("updating renewal info").All()
	if len(updates) != 1 {
		t.Fatalf("reloaded config received %d renewal-info logs, want 1", len(updates))
	}
	if got := updates[0].ContextMap()["identifier"]; got != "example.com" {
		t.Errorf("field added with With arrived as %v, want example.com", got)
	}
}

// A reload that only changes logging must not replace the cache, and the
// reused cache's logging must honor the new config's level. Replacing the
// cache instead would discard every cached certificate because an operator
// raised a log level.
func TestCacheLoggerAppliesReloadedLevel(t *testing.T) {
	withCleanCertCacheState(t)

	first, _ := newObservedApp(zapcore.DebugLevel)
	firstOpts := baseOpts()
	firstOpts.Logger = first.cacheLogger()
	first.provisionCertCache(firstOpts)
	first.publishCertCache()
	captured := firstOpts.Logger

	second, secondLogs := newObservedApp(zapcore.ErrorLevel)
	secondOpts := baseOpts()
	secondOpts.Logger = second.cacheLogger()
	second.provisionCertCache(secondOpts)
	if second.cache != first.cache {
		t.Fatal("a logging-only change must not replace the cache")
	}
	second.publishCertCache()

	// message-filtered for the same reason as above: the reused cache's
	// maintenance goroutine logs through this logger too
	captured.Debug("added certificate to cache")
	if got := secondLogs.FilterMessage("added certificate to cache").Len(); got != 0 {
		t.Errorf("debug cache log reached a config logging at error level: %d entries, want 0", got)
	}
	captured.Error("renewing certificate")
	if got := secondLogs.FilterMessage("renewing certificate").Len(); got != 1 {
		t.Errorf("error-level cache log count is %d, want 1", got)
	}
}

// An unpublished cache belongs to the app that created it, so it logs there —
// this is the state during Provision, before Start publishes anything, and the
// state of a config that fails and is never committed.
func TestCacheLoggerUsesCreatorBeforePublication(t *testing.T) {
	withCleanCertCacheState(t)

	serving, servingLogs := newObservedApp(zapcore.DebugLevel)
	servingOpts := baseOpts()
	servingOpts.Logger = serving.cacheLogger()
	serving.provisionCertCache(servingOpts)
	serving.publishCertCache()

	// an incoming config that changes an option fixed at cache creation gets
	// its own cache, which it has not published
	incoming, incomingLogs := newObservedApp(zapcore.DebugLevel)
	incomingOpts := baseOpts()
	incomingOpts.Capacity++
	incomingOpts.Logger = incoming.cacheLogger()
	incoming.provisionCertCache(incomingOpts)
	if incoming.cache == serving.cache {
		t.Fatal("expected a capacity change to give the incoming config its own cache")
	}
	t.Cleanup(incoming.cache.Stop)

	// message-filtered: both apps own live caches here, and each cache's
	// maintenance goroutine logs "started background certificate maintenance"
	// through the app that owns it at a time the scheduler picks
	incomingOpts.Logger.Error("loading certificate")
	if got := incomingLogs.FilterMessage("loading certificate").Len(); got != 1 {
		t.Errorf("incoming config received %d logs from the cache it owns, want 1", got)
	}
	if got := servingLogs.FilterMessage("loading certificate").Len(); got != 0 {
		t.Errorf("serving config received %d logs from a cache it does not own, want 0", got)
	}
}

// A config's logger is a tee of per-output cores, each with its own level,
// plus name-based include/exclude filtering and optional sampling — and all
// of those decide in Check, not Write. The cache logger therefore has to let
// the delegate's Check pick the sinks; writing to the delegate directly would
// send debug cache entries to error-only outputs and ignore filtering.
func TestCacheLoggerRespectsDelegatePerSinkLevels(t *testing.T) {
	withCleanCertCacheState(t)

	debugCore, debugLogs := observer.New(zapcore.DebugLevel)
	errorCore, errorLogs := observer.New(zapcore.ErrorLevel)
	app := &TLS{logger: zap.New(zapcore.NewTee(debugCore, errorCore))}

	opts := baseOpts()
	opts.Logger = app.cacheLogger()
	app.provisionCertCache(opts)
	app.publishCertCache()

	opts.Logger.Debug("added certificate to cache")
	if got := debugLogs.FilterMessage("added certificate to cache").Len(); got != 1 {
		t.Errorf("debug sink received %d debug cache entries, want 1", got)
	}
	if got := errorLogs.FilterMessage("added certificate to cache").Len(); got != 0 {
		t.Errorf("error-only sink received %d debug cache entries, want 0", got)
	}

	opts.Logger.With(zap.String("identifier", "example.com")).Error("renewing certificate")
	errs := errorLogs.FilterMessage("renewing certificate").All()
	if len(errs) != 1 {
		t.Fatalf("error sink received %d error cache entries, want 1", len(errs))
	}
	if got := errs[0].ContextMap()["identifier"]; got != "example.com" {
		t.Errorf("field reached the delegate as %v, want example.com", got)
	}
}
