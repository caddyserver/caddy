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

// Package network provides transport-neutral DNS-based discovery of upstream
// targets, with result caching. It lives under modules/internal so it can be
// shared between Caddy's own proxies (currently the HTTP reverse_proxy) without
// each copying the resolution and caching logic.
//
// The package intentionally returns neutral [Target] values rather than any
// proxy-specific upstream type; each caller builds its own upstream
// representation from the targets.
package network

import (
	"context"
	"net"
	"strconv"
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
// resolverKey identifies that resolver, so results looked up with different
// resolvers for the same record are cached separately; pass "" for the default
// resolver.
//
// If the lookup fails but returns some records (e.g. a few invalid names were
// filtered out), those records are still used. If it fails with no records and
// grace > 0, the previously cached result keeps being served for up to grace
// past its refresh instead of returning an error. With no cached result, grace
// also suppresses the error and returns no targets, preserving the reverse
// proxy's existing behavior.
//
// Concurrent calls for the same record share one lookup, and no lock is held
// while it runs, so a slow lookup does not delay calls for other records. The
// shared lookup is detached from ctx (and bounded by its own timeout), so the
// caller that started it can go away without failing it for the others; ctx
// still bounds how long this call waits for the result.
func SRV(ctx context.Context, lookup SRVLookupFunc, resolverKey, service, proto, name string, refresh, grace time.Duration, logger *zap.Logger) ([]Target, error) {
	key := srvKey(resolverKey, service, proto, name)
	return srvCache.get(ctx, key, refresh, grace, logger, func(ctx context.Context) ([]Target, error) {
		if c := logger.Check(zapcore.DebugLevel, "refreshing SRV upstreams"); c != nil {
			c.Write(zap.String("service", service), zap.String("proto", proto), zap.String("name", name))
		}

		_, records, err := lookup(ctx, service, proto, name)
		if err != nil {
			// From LookupSRV docs: invalid names are filtered out and an error is
			// returned alongside any remaining results; only treat it as fatal when
			// nothing usable came back.
			if len(records) == 0 {
				return nil, err
			}
			if c := logger.Check(zapcore.WarnLevel, "SRV records filtered"); c != nil {
				c.Write(zap.Error(err))
			}
		}

		targets := make([]Target, len(records))
		for i, rec := range records {
			if c := logger.Check(zapcore.DebugLevel, "discovered SRV record"); c != nil {
				c.Write(zap.String("target", rec.Target), zap.Uint16("port", rec.Port),
					zap.Uint16("priority", rec.Priority), zap.Uint16("weight", rec.Weight))
			}
			targets[i] = Target{
				Host:     rec.Target,
				Port:     strconv.Itoa(int(rec.Port)),
				Priority: rec.Priority,
				Weight:   rec.Weight,
			}
		}
		return targets, nil
	})
}

// ResetSRV removes the cached result for a single SRV record resolved with the
// given resolver (see [SRV] for resolverKey). A lookup for it that is already
// in flight will not write its result back.
func ResetSRV(resolverKey, service, proto, name string) {
	srvCache.reset(srvKey(resolverKey, service, proto, name))
}

// ResetAllSRV clears the entire SRV cache. Lookups already in flight will not
// write their results back.
func ResetAllSRV() {
	srvCache.resetAll()
}

func srvKey(resolverKey, service, proto, name string) string {
	return resolverKey + "\x00" + service + "\x00" + proto + "\x00" + name
}

// IPLookupFunc resolves a host's IP addresses. It matches the signature of
// (*net.Resolver).LookupIP, so callers can pass that directly (and tests can
// inject a stub). network is one of "ip", "ip4", "ip6".
type IPLookupFunc func(ctx context.Context, network, host string) ([]net.IP, error)

// A resolves name's A/AAAA records into targets (one per address, all using the
// given port), caching the result for refresh. network selects the IP versions
// ("ip", "ip4" or "ip6"). lookup is the resolver to use (typically
// (*net.Resolver).LookupIP). resolverKey identifies that resolver, so results
// looked up with different resolvers for the same name are cached separately;
// pass "" for the default resolver.
//
// Concurrency and cancellation behave as described for [SRV].
func A(ctx context.Context, lookup IPLookupFunc, resolverKey, network, name, port string, refresh time.Duration, logger *zap.Logger) ([]Target, error) {
	key := aKey(resolverKey, network, name, port)
	return aCache.get(ctx, key, refresh, 0, logger, func(ctx context.Context) ([]Target, error) {
		if c := logger.Check(zapcore.DebugLevel, "refreshing A upstreams"); c != nil {
			c.Write(zap.String("version", network), zap.String("name", name), zap.String("port", port))
		}

		ips, err := lookup(ctx, network, name)
		if err != nil {
			return nil, err
		}

		targets := make([]Target, len(ips))
		for i, ip := range ips {
			if c := logger.Check(zapcore.DebugLevel, "discovered A record"); c != nil {
				c.Write(zap.String("ip", ip.String()))
			}
			targets[i] = Target{Host: ip.String(), Port: port}
		}
		return targets, nil
	})
}

// ResetA removes the cached result for a single A/AAAA lookup (see [A] for the
// parameters). A lookup for it that is already in flight will not write its
// result back.
func ResetA(resolverKey, network, name, port string) {
	aCache.reset(aKey(resolverKey, network, name, port))
}

// ResetAllA clears the entire A/AAAA cache. Lookups already in flight will not
// write their results back.
func ResetAllA() {
	aCache.resetAll()
}

func aKey(resolverKey, network, name, port string) string {
	return resolverKey + "\x00" + name + "\x00" + port + "\x00" + network
}

var (
	srvCache = newCache("SRV")
	aCache   = newCache("A")
)
