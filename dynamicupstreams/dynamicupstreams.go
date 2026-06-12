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

// Package dynamicupstreams provides transport-neutral DNS-based discovery of
// upstream targets, with result caching. It is shared so that different proxies
// (e.g. the HTTP reverse_proxy and third-party layer4 proxies) can discover
// backends from DNS without each copying the resolution and caching logic.
//
// The package intentionally returns neutral [Target] values rather than any
// proxy-specific upstream type; each caller builds its own upstream
// representation from the targets.
package dynamicupstreams

import (
	"context"
	"net"
	"strconv"
	"sync"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Target is a single discovered upstream endpoint. It carries the SRV priority
// and weight when available (both zero for non-SRV lookups).
type Target struct {
	Host     string
	Port     string
	Priority uint16
	Weight   uint16
}

// SRVLookupFunc resolves SRV records. It matches the signature of
// (*net.Resolver).LookupSRV, so callers can pass that directly (and tests can
// inject a stub).
type SRVLookupFunc func(ctx context.Context, service, proto, name string) (cname string, addrs []*net.SRV, err error)

// SRV resolves the given SRV record into targets, caching the result for
// refresh. lookup is the resolver to use (typically (*net.Resolver).LookupSRV).
//
// If the lookup fails but returns some records (e.g. a few invalid names were
// filtered out), those records are still used. If it fails with no records and
// grace > 0, the previously cached result keeps being served for up to grace
// past its refresh instead of returning an error.
func SRV(ctx context.Context, lookup SRVLookupFunc, service, proto, name string, refresh, grace time.Duration, logger *zap.Logger) ([]Target, error) {
	key := srvKey(service, proto, name)

	// fast path: a fresh cached result under a read lock
	srvMu.RLock()
	cached := srvCache[key]
	srvMu.RUnlock()
	if cached.isFresh() {
		return cached.targets, nil
	}

	srvMu.Lock()
	defer srvMu.Unlock()

	// re-check under the write lock in case another goroutine refreshed it
	cached = srvCache[key]
	if cached.isFresh() {
		return cached.targets, nil
	}

	_, records, err := lookup(ctx, service, proto, name)
	if err != nil {
		// From LookupSRV docs: invalid names are filtered out and an error is
		// returned alongside any remaining results; only treat it as fatal when
		// nothing usable came back.
		if len(records) == 0 {
			if grace > 0 && cached.targets != nil {
				if c := logger.Check(zapcore.ErrorLevel, "SRV lookup failed; using previously cached"); c != nil {
					c.Write(zap.String("service", service), zap.String("proto", proto), zap.String("name", name), zap.Error(err))
				}
				cached.freshness = time.Now().Add(grace - refresh)
				srvCache[key] = cached
				return cached.targets, nil
			}
			return nil, err
		}
		if c := logger.Check(zapcore.WarnLevel, "SRV records filtered"); c != nil {
			c.Write(zap.Error(err))
		}
	}

	targets := make([]Target, len(records))
	for i, rec := range records {
		targets[i] = Target{
			Host:     rec.Target,
			Port:     strconv.Itoa(int(rec.Port)),
			Priority: rec.Priority,
			Weight:   rec.Weight,
		}
	}

	// when inserting a brand-new entry (not replacing a stale one), bound the cache
	if cached.freshness.IsZero() && len(srvCache) >= maxCacheEntries {
		for k := range srvCache {
			delete(srvCache, k)
			break
		}
	}
	srvCache[key] = cacheEntry{refresh: refresh, freshness: time.Now(), targets: targets}
	return targets, nil
}

// ResetSRV removes the cached result for a single SRV record.
func ResetSRV(service, proto, name string) {
	srvMu.Lock()
	delete(srvCache, srvKey(service, proto, name))
	srvMu.Unlock()
}

// ResetAllSRV clears the entire SRV cache.
func ResetAllSRV() {
	srvMu.Lock()
	srvCache = make(map[string]cacheEntry)
	srvMu.Unlock()
}

func srvKey(service, proto, name string) string {
	return service + "\x00" + proto + "\x00" + name
}

const maxCacheEntries = 100

type cacheEntry struct {
	refresh   time.Duration
	freshness time.Time
	targets   []Target
}

func (e cacheEntry) isFresh() bool {
	return !e.freshness.IsZero() && time.Since(e.freshness) < e.refresh
}

// IPLookupFunc resolves a host's IP addresses. It matches the signature of
// (*net.Resolver).LookupIP, so callers can pass that directly (and tests can
// inject a stub). network is one of "ip", "ip4", "ip6".
type IPLookupFunc func(ctx context.Context, network, host string) ([]net.IP, error)

// A resolves name's A/AAAA records into targets (one per address, all using the
// given port), caching the result for refresh. network selects the IP versions
// ("ip", "ip4" or "ip6"). lookup is the resolver to use (typically
// (*net.Resolver).LookupIP).
func A(ctx context.Context, lookup IPLookupFunc, network, name, port string, refresh time.Duration, logger *zap.Logger) ([]Target, error) {
	key := name + "\x00" + port + "\x00" + network

	aMu.RLock()
	cached := aCache[key]
	aMu.RUnlock()
	if cached.isFresh() {
		return cached.targets, nil
	}

	aMu.Lock()
	defer aMu.Unlock()

	cached = aCache[key]
	if cached.isFresh() {
		return cached.targets, nil
	}

	ips, err := lookup(ctx, network, name)
	if err != nil {
		return nil, err
	}

	targets := make([]Target, len(ips))
	for i, ip := range ips {
		targets[i] = Target{Host: ip.String(), Port: port}
	}

	if cached.freshness.IsZero() && len(aCache) >= maxCacheEntries {
		for k := range aCache {
			delete(aCache, k)
			break
		}
	}
	aCache[key] = cacheEntry{refresh: refresh, freshness: time.Now(), targets: targets}
	return targets, nil
}

var (
	srvMu    sync.RWMutex
	srvCache = make(map[string]cacheEntry)

	aMu    sync.RWMutex
	aCache = make(map[string]cacheEntry)
)
