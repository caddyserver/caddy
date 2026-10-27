// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddytls

import (
	"slices"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// cacheLogger returns the logger to hand certmagic for the certificate cache
// this app provisions. It is deliberately indirect, and that indirection is
// what makes a cache safe to reuse across a reload that changes logging.
//
// certmagic captures a cache's logger once, in NewCache, and never replaces
// it. Cache.SetOptions writes only Cache.options; the separate Cache.logger
// field that every cache and maintenance log statement actually uses is left
// untouched. The maintenance goroutine goes further and derives its own logger
// from it exactly once, at startup (certCache.logger.Named("maintenance")). A
// logger given to NewCache is therefore the cache's logger for as long as the
// cache lives.
//
// For a cache reused across a reload, that logger belongs to the wrong config.
// It was built from the creating app's ctx.Logger(), whose cores belong to the
// outgoing config's logging app and are closed when that config is cleaned up.
// Certificate renewal and OCSP failures reported by cache maintenance would
// keep being written to the previous config's destination, which may no longer
// exist, and every logging change the reload made would be ignored for the
// lifetime of the cache.
//
// Neither obvious fix works. Updating Cache.logger in place is not ours to do:
// it is read without synchronization from the maintenance goroutine, so making
// it writable is a certmagic change, not a Caddy one. Replacing the cache
// whenever the logging config changes would be worse than the bug, discarding
// every cached certificate because an operator lowered a log level.
//
// So the logger certmagic captures resolves its destination at log time rather
// than at creation time, following cache ownership through appForCache exactly
// as the GetConfigForCert callback does: a reused cache logs through whichever
// app currently owns it, and a cache that is not published logs through its
// creator. Because the logger is reload-safe for any logging config,
// CacheOptions.Logger is deliberately not one of the fields cacheReusable
// compares — see the comment there.
func (t *TLS) cacheLogger() *zap.Logger {
	// The name is applied here rather than by the caller because zap keeps a
	// logger's name on the Logger and not on the Core, and cacheLogCore
	// forwards entries to the delegate verbatim; naming this logger with the
	// module ID is what puts "tls.cache" (and "tls.cache.maintenance") in the
	// entries the delegate encodes.
	return zap.New(&cacheLogCore{creator: t}).
		Named(string(TLS{}.CaddyModule().ID)).
		Named("cache")
}

// cacheLogCore is a zapcore.Core that writes through the logger of the TLS app
// that currently owns the certificate cache. See (*TLS).cacheLogger for why the
// cache's logger has to be indirect.
//
// Entries are handed to the delegate core unmodified, so the logger name zap
// built up, and the level, time and fields, are all the delegate's to encode,
// and the per-module include/exclude filtering Caddy installs in that core
// still applies. The one thing delegating at the core level cannot carry over
// is the Logger-level options Caddy builds from with_caller and
// with_stacktrace: those are opt-in, and an absent caller field is better than
// one naming a frame inside this file.
type cacheLogCore struct {
	// The app that created the cache this core logs for. It is used to resolve
	// the cache's current owner, and is only logged through directly while it
	// is still that owner.
	creator *TLS

	// fields accumulated by With, replayed on every entry
	fields []zapcore.Field
}

// delegate returns the core to write to.
//
// This takes certCacheMu for reading, via appForCache, and certmagic calls it
// while holding the cache's own lock. So no site in this package may hold
// certCacheMu across a call into a certmagic cache, or the two lock orders
// form a cycle; see the note on the certCacheMu declaration. It is also why
// provisionCertCache creates its cache outside the lock: NewCache starts the
// maintenance goroutine, which logs.
func (c *cacheLogCore) delegate() zapcore.Core {
	owner := c.creator.appForCache()
	if owner == nil || owner.logger == nil {
		return zapcore.NewNopCore()
	}
	return owner.logger.Core()
}

func (c *cacheLogCore) Enabled(lvl zapcore.Level) bool {
	return c.delegate().Enabled(lvl)
}

func (c *cacheLogCore) With(fields []zapcore.Field) zapcore.Core {
	return &cacheLogCore{
		creator: c.creator,
		fields:  append(slices.Clone(c.fields), fields...),
	}
}

func (c *cacheLogCore) Check(ent zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(ent.Level) {
		return ce.AddCore(ent, c)
	}
	return ce
}

func (c *cacheLogCore) Write(ent zapcore.Entry, fields []zapcore.Field) error {
	if len(c.fields) > 0 {
		fields = append(slices.Clone(c.fields), fields...)
	}
	return c.delegate().Write(ent, fields)
}

func (c *cacheLogCore) Sync() error {
	return c.delegate().Sync()
}

// interface guard
var _ zapcore.Core = (*cacheLogCore)(nil)
