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

package network

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sync/singleflight"
)

const (
	// maxCacheEntries is the maximum number of entries kept in each cache.
	maxCacheEntries = 100

	// lookupTimeout bounds a shared lookup, which cannot use any one caller's
	// deadline.
	lookupTimeout = 30 * time.Second

	// maxLookups is the maximum number of distinct lookups allowed to run at
	// once, across both caches. Callers that join a lookup already in flight
	// do not count against it.
	maxLookups = 64

	// maxPendingLookups is the maximum number of lookups allowed to wait for a
	// slot. Beyond that they are shed rather than parked, so a stream of
	// distinct keys cannot pile up goroutines for up to lookupTimeout each.
	maxPendingLookups = 256
)

// errTooManyLookups is returned when the lookup gate is saturated.
var errTooManyLookups = errors.New("too many dynamic upstream lookups in flight")

// lookups is shared by every cache, so total resolver work stays bounded no
// matter how many distinct keys come in.
var lookups = newLookupGate(maxLookups, maxPendingLookups)

// cache holds the results of one kind of lookup, and deduplicates concurrent
// lookups for the same key.
type cache struct {
	kind string // "SRV" or "A", for log messages

	mu      sync.RWMutex
	entries map[string]cacheEntry
	epoch   uint64 // bumped by resetAll; guarded by mu

	group singleflight.Group
}

type cacheEntry struct {
	refresh   time.Duration
	freshness time.Time
	targets   []Target

	// gen counts targeted resets of this key. A lookup writes its result back
	// only if gen (and the cache's epoch) are unchanged since it started, and
	// both are part of the singleflight key, so a caller that arrives after a
	// reset starts its own lookup instead of joining one from before it. It
	// lives on the entry, rather than in a separate map, so it is bounded by
	// maxCacheEntries like everything else.
	gen uint64
}

func newCache(kind string) *cache {
	return &cache{kind: kind, entries: make(map[string]cacheEntry)}
}

func (e cacheEntry) isFresh() bool {
	return !e.freshness.IsZero() && time.Since(e.freshness) < e.refresh
}

// get returns the cached targets for key if they are fresh; otherwise it runs
// lookup, sharing it with concurrent callers for the same key. See [SRV] for
// the meaning of grace.
func (c *cache) get(ctx context.Context, key string, refresh, grace time.Duration, logger *zap.Logger, lookup func(context.Context) ([]Target, error)) ([]Target, error) {
	c.mu.RLock()
	cached := c.entries[key]
	epoch := c.epoch
	c.mu.RUnlock()
	if cached.isFresh() {
		return cached.targets, nil
	}
	gen := cached.gen

	flightKey := strconv.FormatUint(epoch, 10) + "\x00" + strconv.FormatUint(gen, 10) + "\x00" + key
	ch := c.group.DoChan(flightKey, func() (any, error) {
		return c.refresh(ctx, key, epoch, gen, refresh, grace, logger, lookup)
	})

	select {
	case res := <-ch:
		if res.Err != nil {
			return nil, res.Err
		}
		return res.Val.([]Target), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// refresh runs a lookup for key on behalf of every caller sharing the flight.
// epoch and gen are what the caller that started it observed.
func (c *cache) refresh(ctx context.Context, key string, epoch, gen uint64, refresh, grace time.Duration, logger *zap.Logger, lookup func(context.Context) ([]Target, error)) ([]Target, error) {
	// a previous flight may have refreshed the entry since the caller looked
	c.mu.RLock()
	cached := c.entries[key]
	c.mu.RUnlock()
	if cached.isFresh() {
		return cached.targets, nil
	}

	// detached so the caller that started the flight can be cancelled without
	// failing it for the others, but bounded so a stuck resolver cannot
	// outlive every waiter
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), lookupTimeout)
	defer cancel()

	if err := lookups.acquire(ctx); err != nil {
		// slightly stale beats failing, but only if there is something to
		// serve; caching an empty result under load would be worse
		if grace > 0 && len(cached.targets) > 0 {
			if ce := logger.Check(zapcore.WarnLevel, c.kind+" lookup not started; using previously cached"); ce != nil {
				ce.Write(zap.Error(err))
			}
			return c.keepStale(key, epoch, gen, cached, refresh, grace), nil
		}
		return nil, err
	}
	targets, err := lookup(ctx)
	lookups.release()
	if err != nil {
		if grace > 0 {
			if ce := logger.Check(zapcore.ErrorLevel, c.kind+" lookup failed; using previously cached"); ce != nil {
				ce.Write(zap.Error(err))
			}
			return c.keepStale(key, epoch, gen, cached, refresh, grace), nil
		}
		return nil, err
	}

	c.store(key, epoch, gen, cacheEntry{refresh: refresh, freshness: time.Now(), targets: targets})
	return targets, nil
}

// keepStale extends cached so it is served for up to grace past its refresh,
// and returns its targets.
func (c *cache) keepStale(key string, epoch, gen uint64, cached cacheEntry, refresh, grace time.Duration) []Target {
	cached.freshness = time.Now().Add(grace - refresh)
	c.store(key, epoch, gen, cached)
	return cached.targets
}

// store writes e for key, unless key or the whole cache was reset since a
// lookup observed epoch and gen.
func (c *cache) store(key string, epoch, gen uint64, e cacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.epoch != epoch || c.entries[key].gen != gen {
		return
	}
	e.gen = gen
	c.makeRoom(key)
	c.entries[key] = e
}

// reset invalidates key. The entry is kept with its targets dropped and gen
// bumped, rather than deleted, so a lookup for it that is in flight has a
// generation to compare against.
func (c *cache) reset(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.makeRoom(key)
	c.entries[key] = cacheEntry{gen: c.entries[key].gen + 1}
}

// resetAll drops every entry. Bumping epoch covers lookups in flight, so the
// entries themselves can go.
func (c *cache) resetAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]cacheEntry)
	c.epoch++
}

// makeRoom evicts a random entry if the cache is full and key is not already
// in it. c.mu must be held.
func (c *cache) makeRoom(key string) {
	if _, ok := c.entries[key]; ok || len(c.entries) < maxCacheEntries {
		return
	}
	for k := range c.entries {
		delete(c.entries, k)
		break
	}
}

// lookupGate is a counting semaphore with a bounded wait queue.
type lookupGate struct {
	running    chan struct{}
	pending    atomic.Int64
	maxPending int64
}

func newLookupGate(maxRunning, maxPending int) *lookupGate {
	return &lookupGate{
		running:    make(chan struct{}, maxRunning),
		maxPending: int64(maxPending),
	}
}

// acquire takes a slot, waiting until ctx is done. It fails immediately with
// errTooManyLookups if the wait queue is full. A free slot goes to whoever asks
// first, even ahead of queued callers; that keeps the common case to a single
// channel send.
func (g *lookupGate) acquire(ctx context.Context) error {
	select {
	case g.running <- struct{}{}:
		return nil
	default:
	}
	if g.pending.Add(1) > g.maxPending {
		g.pending.Add(-1)
		return errTooManyLookups
	}
	defer g.pending.Add(-1)
	select {
	case g.running <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// release gives back a slot taken by a successful acquire.
func (g *lookupGate) release() {
	<-g.running
}
