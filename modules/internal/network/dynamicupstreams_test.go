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
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"go.uber.org/zap/zaptest/observer"
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

	targets, err := SRV(context.Background(), lookup, "", "svc-cache", "tcp", "x", time.Minute, 0, zap.NewNop())
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
	if _, err := SRV(context.Background(), lookup, "", "svc-cache", "tcp", "x", time.Minute, 0, zap.NewNop()); err != nil {
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
	if _, err := SRV(context.Background(), lookup, "", "svc-err", "tcp", "x", time.Minute, 0, zap.NewNop()); err == nil {
		t.Fatal("expected an error when lookup fails and nothing is cached")
	}
}

func TestSRVGracePeriodServesStale(t *testing.T) {
	ok := func(context.Context, string, string, string) (string, []*net.SRV, error) {
		return "", []*net.SRV{{Target: "a.example.", Port: 1}}, nil
	}
	// tiny refresh so the entry is immediately stale on the next call
	if _, err := SRV(context.Background(), ok, "", "svc-grace", "tcp", "x", time.Nanosecond, time.Hour, zap.NewNop()); err != nil {
		t.Fatalf("seeding cache: %v", err)
	}

	fail := func(context.Context, string, string, string) (string, []*net.SRV, error) {
		return "", nil, errors.New("dns boom")
	}
	// a level-enabled logger so the "using previously cached" error log fires
	targets, err := SRV(context.Background(), fail, "", "svc-grace", "tcp", "x", time.Nanosecond, time.Hour, zaptest.NewLogger(t))
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
	if _, err := SRV(context.Background(), lookup, "", "svc-reset", "tcp", "x", time.Minute, 0, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	ResetSRV("", "svc-reset", "tcp", "x")
	if _, err := SRV(context.Background(), lookup, "", "svc-reset", "tcp", "x", time.Minute, 0, zap.NewNop()); err != nil {
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

	targets, err := A(context.Background(), lookup, "", "ip", "db.a-test", "5432", time.Minute, zap.NewNop())
	if err != nil {
		t.Fatalf("A: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("targets = %d, want 2", len(targets))
	}
	if targets[0].Host != "10.0.0.1" || targets[0].Port != "5432" {
		t.Errorf("unexpected first target: %+v", targets[0])
	}

	if _, err := A(context.Background(), lookup, "", "ip", "db.a-test", "5432", time.Minute, zap.NewNop()); err != nil {
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
	if _, err := A(context.Background(), lookup, "", "ip", "db.a-err", "5432", time.Minute, zap.NewNop()); err == nil {
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
	targets, err := SRV(context.Background(), lookup, "", "svc-filtered", "tcp", "x", time.Minute, 0, zaptest.NewLogger(t))
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
	if _, err := SRV(context.Background(), lookup, "", "svc-reset-all", "tcp", "x", time.Minute, 0, zap.NewNop()); err != nil {
		t.Fatalf("SRV: %v", err)
	}
	srvCache.mu.RLock()
	populated := len(srvCache.entries) > 0
	srvCache.mu.RUnlock()
	if !populated {
		t.Fatal("expected the SRV cache to be populated before reset")
	}

	ResetAllSRV()

	srvCache.mu.RLock()
	n := len(srvCache.entries)
	srvCache.mu.RUnlock()
	if n != 0 {
		t.Fatalf("srvCache len = %d after ResetAllSRV, want 0", n)
	}
}

// TestSRVCacheBound verifies that inserting a brand-new entry once the cache is
// full evicts an existing one so the cache stays bounded.
func TestSRVCacheBound(t *testing.T) {
	ResetAllSRV()

	lookup := func(context.Context, string, string, string) (string, []*net.SRV, error) {
		return "", []*net.SRV{{Target: "a.example.", Port: 1}}, nil
	}
	for i := 0; i < maxCacheEntries+5; i++ {
		name := fmt.Sprintf("svc-bound-%d", i)
		if _, err := SRV(context.Background(), lookup, "", name, "tcp", "x", time.Minute, 0, zap.NewNop()); err != nil {
			t.Fatalf("SRV[%d]: %v", i, err)
		}
	}
	srvCache.mu.RLock()
	n := len(srvCache.entries)
	srvCache.mu.RUnlock()
	if n > maxCacheEntries {
		t.Fatalf("srvCache len = %d, want <= %d (cache must stay bounded)", n, maxCacheEntries)
	}
}

// TestSRVResolverKeyIsolatesCache verifies that two lookups for the same SRV
// record but with different resolver keys do not share a cache entry.
func TestSRVResolverKeyIsolatesCache(t *testing.T) {
	ResetAllSRV()
	t.Cleanup(ResetAllSRV)

	lookupA := func(context.Context, string, string, string) (string, []*net.SRV, error) {
		return "", []*net.SRV{{Target: "a.example.", Port: 1}}, nil
	}
	lookupB := func(context.Context, string, string, string) (string, []*net.SRV, error) {
		return "", []*net.SRV{{Target: "b.example.", Port: 2}}, nil
	}

	ta, err := SRV(context.Background(), lookupA, "resolver-a", "svc", "tcp", "x", time.Minute, 0, zap.NewNop())
	if err != nil {
		t.Fatalf("resolver-a: %v", err)
	}
	tb, err := SRV(context.Background(), lookupB, "resolver-b", "svc", "tcp", "x", time.Minute, 0, zap.NewNop())
	if err != nil {
		t.Fatalf("resolver-b: %v", err)
	}
	if len(ta) != 1 || ta[0].Host != "a.example." {
		t.Fatalf("resolver-a targets = %+v, want a.example.", ta)
	}
	if len(tb) != 1 || tb[0].Host != "b.example." {
		t.Fatalf("resolver-b targets = %+v, want b.example. (resolver-a's entry leaked across resolvers)", tb)
	}
}

// TestAResolverKeyIsolatesCache is the A-cache equivalent of the above.
func TestAResolverKeyIsolatesCache(t *testing.T) {
	ResetAllA()

	lookupA := func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.0.0.1")}, nil
	}
	lookupB := func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.0.0.2")}, nil
	}

	ta, err := A(context.Background(), lookupA, "resolver-a", "ip", "db.iso", "5432", time.Minute, zap.NewNop())
	if err != nil {
		t.Fatalf("resolver-a: %v", err)
	}
	tb, err := A(context.Background(), lookupB, "resolver-b", "ip", "db.iso", "5432", time.Minute, zap.NewNop())
	if err != nil {
		t.Fatalf("resolver-b: %v", err)
	}
	if len(ta) != 1 || ta[0].Host != "10.0.0.1" {
		t.Fatalf("resolver-a targets = %+v, want 10.0.0.1", ta)
	}
	if len(tb) != 1 || tb[0].Host != "10.0.0.2" {
		t.Fatalf("resolver-b targets = %+v, want 10.0.0.2 (resolver-a's entry leaked across resolvers)", tb)
	}
}

// TestACacheBound verifies the same bounding behavior for the A cache.
func TestACacheBound(t *testing.T) {
	ResetAllA()

	lookup := func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.0.0.1")}, nil
	}
	for i := 0; i < maxCacheEntries+5; i++ {
		name := fmt.Sprintf("db.bound-%d", i)
		if _, err := A(context.Background(), lookup, "", "ip", name, "5432", time.Minute, zap.NewNop()); err != nil {
			t.Fatalf("A[%d]: %v", i, err)
		}
	}
	aCache.mu.RLock()
	n := len(aCache.entries)
	aCache.mu.RUnlock()
	if n > maxCacheEntries {
		t.Fatalf("aCache len = %d, want <= %d (cache must stay bounded)", n, maxCacheEntries)
	}
}

// TestSRVConcurrentRefreshDeduplicates verifies that two concurrent callers
// missing the cache for the same key result in a single lookup. Depending on
// scheduling the second caller either joins the first one's in-flight lookup
// or is served the result it cached; this test does not force one over the
// other, it asserts deduplication (exactly one lookup). Run under -race it also guards against
// data races on the shared cache.
func TestSRVConcurrentRefreshDeduplicates(t *testing.T) {
	ResetAllSRV()

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
			<-release // hold the lookup open while the second goroutine starts
		}
		return "", []*net.SRV{{Target: "a.example.", Port: 1}}, nil
	}

	done := make(chan struct{}, 2)
	// G1: starts the lookup and blocks inside it.
	go func() {
		_, _ = SRV(context.Background(), lookup, "", "svc-conc", "tcp", "x", time.Minute, 0, zap.NewNop())
		done <- struct{}{}
	}()
	<-inLookup // G1 is mid-lookup; cache is still empty

	// G2: a second caller for the same key; it must not start a lookup of its
	// own.
	go func() {
		_, _ = SRV(context.Background(), lookup, "", "svc-conc", "tcp", "x", time.Minute, 0, zap.NewNop())
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
	ResetAllA()

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
		_, _ = A(context.Background(), lookup, "", "ip", "db.conc", "5432", time.Minute, zap.NewNop())
		done <- struct{}{}
	}()
	<-inLookup

	// Second caller for the same key; ordering is enforced by the channels,
	// not by timing (see the SRV test above).
	go func() {
		_, _ = A(context.Background(), lookup, "", "ip", "db.conc", "5432", time.Minute, zap.NewNop())
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

func TestSRVGracePeriodWithoutCachedResult(t *testing.T) {
	ResetSRV("", "svc-cold-grace", "tcp", "x")
	t.Cleanup(func() { ResetSRV("", "svc-cold-grace", "tcp", "x") })
	lookup := func(context.Context, string, string, string) (string, []*net.SRV, error) {
		return "", nil, errors.New("dns boom")
	}
	targets, err := SRV(context.Background(), lookup, "", "svc-cold-grace", "tcp", "x", time.Minute, time.Minute, zap.NewNop())
	if err != nil || len(targets) != 0 {
		t.Fatalf("cold-cache failure with grace: targets = %v, err = %v; want no targets and no error", targets, err)
	}
}

func TestDiscoveryLoggingOnlyOnRefresh(t *testing.T) {
	t.Run("SRV", func(t *testing.T) {
		ResetSRV("", "svc-log", "tcp", "x")
		t.Cleanup(func() { ResetSRV("", "svc-log", "tcp", "x") })
		core, logs := observer.New(zap.DebugLevel)
		logger := zap.New(core)
		lookup := func(context.Context, string, string, string) (string, []*net.SRV, error) {
			return "", []*net.SRV{{Target: "a.example.", Port: 5432, Priority: 1, Weight: 10}}, nil
		}
		for range 2 {
			if _, err := SRV(context.Background(), lookup, "", "svc-log", "tcp", "x", time.Minute, 0, logger); err != nil {
				t.Fatal(err)
			}
		}
		if got := logs.FilterMessage("refreshing SRV upstreams").Len(); got != 1 {
			t.Fatalf("refresh logs = %d, want 1", got)
		}
		records := logs.FilterMessage("discovered SRV record").All()
		if len(records) != 1 {
			t.Fatalf("discovery logs = %d, want 1", len(records))
		}
		fields := records[0].ContextMap()
		if fields["target"] != "a.example." || fields["port"] != uint16(5432) || fields["priority"] != uint16(1) || fields["weight"] != uint16(10) {
			t.Fatalf("unexpected discovery log fields: %v", fields)
		}
	})
	t.Run("A", func(t *testing.T) {
		ResetAllA()
		core, logs := observer.New(zap.DebugLevel)
		logger := zap.New(core)
		lookup := func(context.Context, string, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("10.0.0.1")}, nil
		}
		for range 2 {
			if _, err := A(context.Background(), lookup, "", "ip", "db.log", "5432", time.Minute, logger); err != nil {
				t.Fatal(err)
			}
		}
		if got := logs.FilterMessage("refreshing A upstreams").Len(); got != 1 {
			t.Fatalf("refresh logs = %d, want 1", got)
		}
		records := logs.FilterMessage("discovered A record").All()
		if len(records) != 1 {
			t.Fatalf("discovery logs = %d, want 1", len(records))
		}
		if got := records[0].ContextMap()["ip"]; got != "10.0.0.1" {
			t.Fatalf("logged IP = %v, want 10.0.0.1", got)
		}
	})
}

// blockingSRV returns an SRV lookup that sends its context on started and then
// blocks until release is closed, answering with target.
func blockingSRV(target string, started chan<- context.Context, release <-chan struct{}) SRVLookupFunc {
	return func(ctx context.Context, _, _, _ string) (string, []*net.SRV, error) {
		started <- ctx
		<-release
		return "", []*net.SRV{{Target: target, Port: 1}}, nil
	}
}

// instantSRV returns an SRV lookup that answers with target right away,
// counting its calls.
func instantSRV(target string, calls *atomic.Int32) SRVLookupFunc {
	return func(context.Context, string, string, string) (string, []*net.SRV, error) {
		calls.Add(1)
		return "", []*net.SRV{{Target: target, Port: 1}}, nil
	}
}

type srvResult struct {
	targets []Target
	err     error
}

func goSRV(ctx context.Context, lookup SRVLookupFunc, service string) <-chan srvResult {
	ch := make(chan srvResult, 1)
	go func() {
		targets, err := SRV(ctx, lookup, "", service, "tcp", "x", time.Minute, 0, zap.NewNop())
		ch <- srvResult{targets, err}
	}()
	return ch
}

func waitResult(t *testing.T, ch <-chan srvResult) srvResult {
	t.Helper()
	select {
	case res := <-ch:
		return res
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for SRV to return")
		return srvResult{}
	}
}

// TestSlowLookupDoesNotBlockOtherKeys is a regression test for #7946: a slow
// lookup for one key used to hold the cache lock across the DNS call, blocking
// every other key.
func TestSlowLookupDoesNotBlockOtherKeys(t *testing.T) {
	started := make(chan context.Context, 1)
	release := make(chan struct{})
	slow := goSRV(context.Background(), blockingSRV("slow.example.", started, release), "svc-slow")
	<-started

	var calls atomic.Int32
	res := waitResult(t, goSRV(context.Background(), instantSRV("fast.example.", &calls), "svc-fast"))
	if res.err != nil || len(res.targets) != 1 || res.targets[0].Host != "fast.example." {
		t.Fatalf("unrelated key while another is slow: targets = %v, err = %v", res.targets, res.err)
	}

	close(release)
	if res := waitResult(t, slow); res.err != nil {
		t.Fatalf("slow lookup: %v", res.err)
	}
}

// TestCallerCancellationDoesNotFailSharedLookup checks that a shared lookup
// outlives the caller that started it: that caller returns promptly with its
// own context error, while another caller on the same flight still gets the
// result. The lookup must still be bounded by a deadline of its own.
func TestCallerCancellationDoesNotFailSharedLookup(t *testing.T) {
	started := make(chan context.Context, 2)
	release := make(chan struct{})
	lookup := blockingSRV("a.example.", started, release)

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leader := goSRV(leaderCtx, lookup, "svc-leader")
	lookupCtx := <-started
	follower := goSRV(context.Background(), lookup, "svc-leader")

	cancelLeader()
	if res := waitResult(t, leader); !errors.Is(res.err, context.Canceled) {
		t.Fatalf("cancelled caller: err = %v, want context.Canceled", res.err)
	}
	if err := lookupCtx.Err(); err != nil {
		t.Fatalf("shared lookup was cancelled with its first caller: %v", err)
	}
	if _, ok := lookupCtx.Deadline(); !ok {
		t.Fatal("shared lookup has no deadline of its own")
	}

	close(release)
	res := waitResult(t, follower)
	if res.err != nil || len(res.targets) != 1 {
		t.Fatalf("remaining caller: targets = %v, err = %v", res.targets, res.err)
	}
	select {
	case <-started:
		t.Fatal("remaining caller started a second lookup instead of sharing the first")
	default:
	}
}

// TestResetDuringLookup checks that a reset invalidates a lookup already in
// flight: a caller arriving after the reset starts a new lookup rather than
// joining the old one, and the old one, finishing last, does not overwrite the
// newer result.
func TestResetDuringLookup(t *testing.T) {
	started := make(chan context.Context, 1)
	release := make(chan struct{})
	old := goSRV(context.Background(), blockingSRV("old.example.", started, release), "svc-reset-inflight")
	<-started

	ResetSRV("", "svc-reset-inflight", "tcp", "x")

	var calls atomic.Int32
	res := waitResult(t, goSRV(context.Background(), instantSRV("new.example.", &calls), "svc-reset-inflight"))
	if res.err != nil || calls.Load() != 1 || res.targets[0].Host != "new.example." {
		t.Fatalf("caller after reset: targets = %v, err = %v, lookups = %d; want its own lookup", res.targets, res.err, calls.Load())
	}

	close(release)
	if res := waitResult(t, old); res.err != nil {
		t.Fatalf("pre-reset lookup: %v", res.err)
	}

	res = waitResult(t, goSRV(context.Background(), instantSRV("unused.example.", &calls), "svc-reset-inflight"))
	if res.err != nil || res.targets[0].Host != "new.example." {
		t.Fatalf("cached after both lookups: targets = %v, err = %v; want new.example.", res.targets, res.err)
	}
}

// TestResetAllDuringLookup checks that a full reset also keeps an in-flight
// lookup from repopulating the cache.
func TestResetAllDuringLookup(t *testing.T) {
	started := make(chan context.Context, 1)
	release := make(chan struct{})
	old := goSRV(context.Background(), blockingSRV("old.example.", started, release), "svc-reset-all-inflight")
	<-started

	ResetAllSRV()
	close(release)
	if res := waitResult(t, old); res.err != nil {
		t.Fatalf("pre-reset lookup: %v", res.err)
	}

	srvCache.mu.RLock()
	_, ok := srvCache.entries[srvKey("", "svc-reset-all-inflight", "tcp", "x")]
	srvCache.mu.RUnlock()
	if ok {
		t.Fatal("lookup that started before ResetAllSRV wrote its result back")
	}
}

func TestLookupGate(t *testing.T) {
	g := newLookupGate(2, 1)
	for i := range 2 {
		if err := g.acquire(context.Background()); err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
	}

	// the third caller queues; with the queue then full, a fourth is shed
	queued := make(chan error, 1)
	queuedCtx, cancelQueued := context.WithCancel(context.Background())
	go func() { queued <- g.acquire(queuedCtx) }()
	for g.pending.Load() != 1 {
		time.Sleep(time.Millisecond)
	}
	if err := g.acquire(context.Background()); !errors.Is(err, errTooManyLookups) {
		t.Fatalf("acquire with full queue: err = %v, want errTooManyLookups", err)
	}

	// a queued caller can give up
	cancelQueued()
	if err := <-queued; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled queued acquire: err = %v, want context.Canceled", err)
	}

	// and a released slot is usable again
	g.release()
	if err := g.acquire(context.Background()); err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
}

// saturateLookups fills every slot of the shared lookup gate, and optionally
// its wait queue too, until the test ends.
func saturateLookups(t *testing.T, fillQueue bool) {
	t.Helper()
	for range cap(lookups.running) {
		lookups.running <- struct{}{}
	}
	if fillQueue {
		lookups.pending.Add(lookups.maxPending)
	}
	t.Cleanup(func() {
		if fillQueue {
			lookups.pending.Add(-lookups.maxPending)
		}
		for range cap(lookups.running) {
			lookups.release()
		}
	})
}

// TestLookupsAreBounded checks the gate is wired in: while it is saturated a
// new key does not reach the resolver and its caller can still give up, and
// the lookup proceeds once slots free up.
func TestLookupsAreBounded(t *testing.T) {
	var calls atomic.Int32
	lookup := instantSRV("a.example.", &calls)

	t.Run("saturated", func(t *testing.T) {
		saturateLookups(t, false)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		if res := waitResult(t, goSRV(ctx, lookup, "svc-bounded")); !errors.Is(res.err, context.DeadlineExceeded) {
			t.Fatalf("caller while saturated: err = %v, want its own deadline", res.err)
		}
		if n := calls.Load(); n != 0 {
			t.Fatalf("resolver called %d times while the gate was saturated", n)
		}
	})

	res := waitResult(t, goSRV(context.Background(), lookup, "svc-bounded"))
	if res.err != nil || len(res.targets) != 1 {
		t.Fatalf("after slots freed: targets = %v, err = %v", res.targets, res.err)
	}
}

// TestShedLookups checks what happens when the gate's queue is full too: a
// stale SRV entry is served if there is a grace period; otherwise the lookup
// fails without reaching the resolver.
func TestShedLookups(t *testing.T) {
	var calls atomic.Int32
	seed := instantSRV("stale.example.", &calls)
	if _, err := SRV(context.Background(), seed, "", "svc-shed-stale", "tcp", "x", time.Nanosecond, time.Hour, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	if _, err := SRV(context.Background(), seed, "", "svc-shed-nograce", "tcp", "x", time.Nanosecond, 0, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	calls.Store(0)

	saturateLookups(t, true)

	targets, err := SRV(context.Background(), seed, "", "svc-shed-stale", "tcp", "x", time.Nanosecond, time.Hour, zap.NewNop())
	if err != nil || len(targets) != 1 || targets[0].Host != "stale.example." {
		t.Fatalf("shed with grace and a stale entry: targets = %v, err = %v; want the stale entry", targets, err)
	}
	for _, tc := range []struct {
		name  string
		grace time.Duration
	}{
		{name: "svc-shed-nograce"},
		{name: "svc-shed-cold", grace: time.Hour},
	} {
		if _, err := SRV(context.Background(), seed, "", tc.name, "tcp", "x", time.Nanosecond, tc.grace, zap.NewNop()); !errors.Is(err, errTooManyLookups) {
			t.Errorf("%s: err = %v, want errTooManyLookups", tc.name, err)
		}
	}
	ipLookup := func(context.Context, string, string) ([]net.IP, error) {
		calls.Add(1)
		return []net.IP{net.ParseIP("10.0.0.1")}, nil
	}
	if _, err := A(context.Background(), ipLookup, "", "ip", "db.shed", "80", time.Minute, zap.NewNop()); !errors.Is(err, errTooManyLookups) {
		t.Errorf("A: err = %v, want errTooManyLookups", err)
	}
	if n := calls.Load(); n != 0 {
		t.Fatalf("resolver called %d times while lookups were being shed", n)
	}
}

func TestResetA(t *testing.T) {
	var calls atomic.Int32
	lookup := func(context.Context, string, string) ([]net.IP, error) {
		calls.Add(1)
		return []net.IP{net.ParseIP("10.0.0.1")}, nil
	}
	get := func() {
		t.Helper()
		if _, err := A(context.Background(), lookup, "", "ip", "db.reset", "80", time.Minute, zap.NewNop()); err != nil {
			t.Fatal(err)
		}
	}

	get()
	get()
	ResetA("", "ip", "db.reset", "80")
	get()
	ResetAllA()
	get()
	if n := calls.Load(); n != 3 {
		t.Fatalf("lookup calls = %d, want 3 (one, cached, then one after each reset)", n)
	}
}
