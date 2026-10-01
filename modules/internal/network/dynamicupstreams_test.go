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
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

func TestSRVResolvesAndCaches(t *testing.T) {
	calls := 0
	lookup := func(context.Context, string, string, string) (string, []*net.SRV, error) {
		calls++
		return "", []*net.SRV{
			{Target: "a.example.", Port: 5432, Priority: 1, Weight: 10},
			{Target: "b.example.", Port: 5433, Priority: 1, Weight: 20},
		}, nil
	}

	targets, err := SRV(context.Background(), lookup, "svc-cache", "tcp", "x", time.Minute, 0, zap.NewNop())
	if err != nil {
		t.Fatalf("SRV: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("targets = %d, want 2", len(targets))
	}
	if targets[0].Host != "a.example." || targets[0].Port != "5432" || targets[0].Weight != 10 {
		t.Errorf("unexpected first target: %+v", targets[0])
	}

	// second call within refresh must be served from cache (no extra lookup)
	if _, err := SRV(context.Background(), lookup, "svc-cache", "tcp", "x", time.Minute, 0, zap.NewNop()); err != nil {
		t.Fatalf("SRV (cached): %v", err)
	}
	if calls != 1 {
		t.Errorf("lookup calls = %d, want 1 (cached)", calls)
	}
}

func TestSRVErrorWithoutGrace(t *testing.T) {
	lookup := func(context.Context, string, string, string) (string, []*net.SRV, error) {
		return "", nil, errors.New("dns boom")
	}
	if _, err := SRV(context.Background(), lookup, "svc-err", "tcp", "x", time.Minute, 0, zap.NewNop()); err == nil {
		t.Fatal("expected an error when lookup fails and nothing is cached")
	}
}

func TestSRVGracePeriodServesStale(t *testing.T) {
	ok := func(context.Context, string, string, string) (string, []*net.SRV, error) {
		return "", []*net.SRV{{Target: "a.example.", Port: 1}}, nil
	}
	// tiny refresh so the entry is immediately stale on the next call
	if _, err := SRV(context.Background(), ok, "svc-grace", "tcp", "x", time.Nanosecond, time.Hour, zap.NewNop()); err != nil {
		t.Fatalf("seeding cache: %v", err)
	}

	fail := func(context.Context, string, string, string) (string, []*net.SRV, error) {
		return "", nil, errors.New("dns boom")
	}
	// a level-enabled logger so the "using previously cached" error log fires
	targets, err := SRV(context.Background(), fail, "svc-grace", "tcp", "x", time.Nanosecond, time.Hour, zaptest.NewLogger(t))
	if err != nil {
		t.Fatalf("grace period should suppress the error: %v", err)
	}
	if len(targets) != 1 {
		t.Errorf("expected the stale cached target to be served, got %d", len(targets))
	}
}

func TestResetSRV(t *testing.T) {
	calls := 0
	lookup := func(context.Context, string, string, string) (string, []*net.SRV, error) {
		calls++
		return "", []*net.SRV{{Target: "a.example.", Port: 1}}, nil
	}
	if _, err := SRV(context.Background(), lookup, "svc-reset", "tcp", "x", time.Minute, 0, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	ResetSRV("svc-reset", "tcp", "x")
	if _, err := SRV(context.Background(), lookup, "svc-reset", "tcp", "x", time.Minute, 0, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Errorf("lookup calls = %d, want 2 (cache was reset between calls)", calls)
	}
}

func TestAResolvesAndCaches(t *testing.T) {
	calls := 0
	lookup := func(context.Context, string, string) ([]net.IP, error) {
		calls++
		return []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")}, nil
	}

	targets, err := A(context.Background(), lookup, "ip", "db.a-test", "5432", time.Minute, zap.NewNop())
	if err != nil {
		t.Fatalf("A: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("targets = %d, want 2", len(targets))
	}
	if targets[0].Host != "10.0.0.1" || targets[0].Port != "5432" {
		t.Errorf("unexpected first target: %+v", targets[0])
	}

	if _, err := A(context.Background(), lookup, "ip", "db.a-test", "5432", time.Minute, zap.NewNop()); err != nil {
		t.Fatalf("A (cached): %v", err)
	}
	if calls != 1 {
		t.Errorf("lookup calls = %d, want 1 (cached)", calls)
	}
}

func TestAError(t *testing.T) {
	lookup := func(context.Context, string, string) ([]net.IP, error) {
		return nil, errors.New("dns boom")
	}
	if _, err := A(context.Background(), lookup, "ip", "db.a-err", "5432", time.Minute, zap.NewNop()); err == nil {
		t.Fatal("expected an error when the A lookup fails")
	}
}

// TestSRVFilteredRecords covers the LookupSRV semantics where invalid names are
// filtered out and an error is returned alongside the usable remainder: the
// usable records must still be returned (the error is downgraded to a warning).
func TestSRVFilteredRecords(t *testing.T) {
	lookup := func(context.Context, string, string, string) (string, []*net.SRV, error) {
		return "", []*net.SRV{{Target: "ok.example.", Port: 5432, Priority: 1, Weight: 10}},
			errors.New("some SRV names were filtered out")
	}
	// a level-enabled logger so the "SRV records filtered" warning fires
	targets, err := SRV(context.Background(), lookup, "svc-filtered", "tcp", "x", time.Minute, 0, zaptest.NewLogger(t))
	if err != nil {
		t.Fatalf("usable records must be returned despite the partial error: %v", err)
	}
	if len(targets) != 1 || targets[0].Host != "ok.example." {
		t.Fatalf("unexpected targets: %+v", targets)
	}
}

// TestResetAllSRV verifies that the whole SRV cache is dropped.
func TestResetAllSRV(t *testing.T) {
	lookup := func(context.Context, string, string, string) (string, []*net.SRV, error) {
		return "", []*net.SRV{{Target: "a.example.", Port: 1}}, nil
	}
	if _, err := SRV(context.Background(), lookup, "svc-reset-all", "tcp", "x", time.Minute, 0, zap.NewNop()); err != nil {
		t.Fatalf("SRV: %v", err)
	}
	srvMu.RLock()
	populated := len(srvCache) > 0
	srvMu.RUnlock()
	if !populated {
		t.Fatal("expected the SRV cache to be populated before reset")
	}

	ResetAllSRV()

	srvMu.RLock()
	n := len(srvCache)
	srvMu.RUnlock()
	if n != 0 {
		t.Fatalf("srvCache len = %d after ResetAllSRV, want 0", n)
	}
}

// TestSRVCacheBound verifies that inserting a brand-new entry once the cache is
// full evicts an existing one so the cache stays bounded.
func TestSRVCacheBound(t *testing.T) {
	srvMu.Lock()
	srvCache = make(map[string]cacheEntry)
	srvMu.Unlock()

	lookup := func(context.Context, string, string, string) (string, []*net.SRV, error) {
		return "", []*net.SRV{{Target: "a.example.", Port: 1}}, nil
	}
	for i := 0; i < maxCacheEntries+5; i++ {
		name := fmt.Sprintf("svc-bound-%d", i)
		if _, err := SRV(context.Background(), lookup, name, "tcp", "x", time.Minute, 0, zap.NewNop()); err != nil {
			t.Fatalf("SRV[%d]: %v", i, err)
		}
	}
	srvMu.RLock()
	n := len(srvCache)
	srvMu.RUnlock()
	if n > maxCacheEntries {
		t.Fatalf("srvCache len = %d, want <= %d (cache must stay bounded)", n, maxCacheEntries)
	}
}

// TestACacheBound verifies the same bounding behavior for the A cache.
func TestACacheBound(t *testing.T) {
	aMu.Lock()
	aCache = make(map[string]cacheEntry)
	aMu.Unlock()

	lookup := func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.0.0.1")}, nil
	}
	for i := 0; i < maxCacheEntries+5; i++ {
		name := fmt.Sprintf("db.bound-%d", i)
		if _, err := A(context.Background(), lookup, "ip", name, "5432", time.Minute, zap.NewNop()); err != nil {
			t.Fatalf("A[%d]: %v", i, err)
		}
	}
	aMu.RLock()
	n := len(aCache)
	aMu.RUnlock()
	if n > maxCacheEntries {
		t.Fatalf("aCache len = %d, want <= %d (cache must stay bounded)", n, maxCacheEntries)
	}
}

// TestSRVConcurrentRefreshDeduplicates verifies that two concurrent callers
// missing the cache for the same key result in a single lookup: the first
// performs it while holding the write lock, and the second is served the
// cached result once the first releases. Depending on scheduling the second
// caller may be served by either the read-lock fast path or the write-lock
// re-check — this test does not force one branch over the other; it asserts
// deduplication (exactly one lookup). Run under -race it also guards against
// data races on the shared cache.
func TestSRVConcurrentRefreshDeduplicates(t *testing.T) {
	srvMu.Lock()
	srvCache = make(map[string]cacheEntry)
	srvMu.Unlock()

	var calls int
	var mu sync.Mutex
	inLookup := make(chan struct{})
	release := make(chan struct{})
	lookup := func(context.Context, string, string, string) (string, []*net.SRV, error) {
		mu.Lock()
		calls++
		first := calls == 1
		mu.Unlock()
		if first {
			close(inLookup)
			<-release // hold the write lock until the second goroutine is queued
		}
		return "", []*net.SRV{{Target: "a.example.", Port: 1}}, nil
	}

	done := make(chan struct{}, 2)
	// G1: takes the write lock and blocks inside lookup.
	go func() {
		_, _ = SRV(context.Background(), lookup, "svc-conc", "tcp", "x", time.Minute, 0, zap.NewNop())
		done <- struct{}{}
	}()
	<-inLookup // G1 now holds the write lock; cache is still empty

	// G2: a second caller for the same key. While G1 holds the write lock, G2
	// cannot acquire srvMu at all (a reader blocks behind the writer); once G1
	// populates the cache and releases, G2 observes the cached entry and
	// performs no lookup. Ordering here is enforced by the channels below, not
	// by timing.
	go func() {
		_, _ = SRV(context.Background(), lookup, "svc-conc", "tcp", "x", time.Minute, 0, zap.NewNop())
		done <- struct{}{}
	}()

	close(release) // G1 populates the cache and releases the lock
	<-done
	<-done

	mu.Lock()
	got := calls
	mu.Unlock()
	if got != 1 {
		t.Fatalf("lookup calls = %d, want 1 (concurrent callers for the same key must share one lookup)", got)
	}
}

// TestAConcurrentRefreshDeduplicates is the A-cache equivalent of the above:
// it asserts deduplication (one lookup for two concurrent callers) and, under
// -race, race-safety; it does not force a particular locking branch.
func TestAConcurrentRefreshDeduplicates(t *testing.T) {
	aMu.Lock()
	aCache = make(map[string]cacheEntry)
	aMu.Unlock()

	var calls int
	var mu sync.Mutex
	inLookup := make(chan struct{})
	release := make(chan struct{})
	lookup := func(context.Context, string, string) ([]net.IP, error) {
		mu.Lock()
		calls++
		first := calls == 1
		mu.Unlock()
		if first {
			close(inLookup)
			<-release
		}
		return []net.IP{net.ParseIP("10.0.0.1")}, nil
	}

	done := make(chan struct{}, 2)
	go func() {
		_, _ = A(context.Background(), lookup, "ip", "db.conc", "5432", time.Minute, zap.NewNop())
		done <- struct{}{}
	}()
	<-inLookup

	// Second caller for the same key; ordering is enforced by the channels,
	// not by timing (see the SRV test above).
	go func() {
		_, _ = A(context.Background(), lookup, "ip", "db.conc", "5432", time.Minute, zap.NewNop())
		done <- struct{}{}
	}()

	close(release)
	<-done
	<-done

	mu.Lock()
	got := calls
	mu.Unlock()
	if got != 1 {
		t.Fatalf("lookup calls = %d, want 1 (concurrent callers for the same key must share one lookup)", got)
	}
}
