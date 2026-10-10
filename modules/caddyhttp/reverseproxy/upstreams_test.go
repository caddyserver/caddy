package reverseproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
)

func TestResolveIpVersion(t *testing.T) {
	falseBool := false
	trueBool := true
	tests := []struct {
		Versions          *IPVersions
		expectedIpVersion string
	}{
		{
			Versions:          &IPVersions{IPv4: &trueBool},
			expectedIpVersion: "ip4",
		},
		{
			Versions:          &IPVersions{IPv4: &falseBool},
			expectedIpVersion: "ip",
		},
		{
			Versions:          &IPVersions{IPv4: &trueBool, IPv6: &falseBool},
			expectedIpVersion: "ip4",
		},
		{
			Versions:          &IPVersions{IPv6: &trueBool},
			expectedIpVersion: "ip6",
		},
		{
			Versions:          &IPVersions{IPv6: &falseBool},
			expectedIpVersion: "ip",
		},
		{
			Versions:          &IPVersions{IPv6: &trueBool, IPv4: &falseBool},
			expectedIpVersion: "ip6",
		},
		{
			Versions:          &IPVersions{},
			expectedIpVersion: "ip",
		},
		{
			Versions:          &IPVersions{IPv4: &trueBool, IPv6: &trueBool},
			expectedIpVersion: "ip",
		},
		{
			Versions:          &IPVersions{IPv4: &falseBool, IPv6: &falseBool},
			expectedIpVersion: "ip",
		},
	}
	for _, test := range tests {
		ipVersion := resolveIpVersion(test.Versions)
		if ipVersion != test.expectedIpVersion {
			t.Errorf("resolveIpVersion(): Expected %s got %s", test.expectedIpVersion, ipVersion)
		}
	}
}

// fakeSRVResolver implements srvResolver so tests can control the timing and
// results of SRV lookups without a real DNS server.
type fakeSRVResolver struct {
	lookupSRV func(ctx context.Context, service, proto, name string) (string, []*net.SRV, error)
}

func (f *fakeSRVResolver) LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error) {
	return f.lookupSRV(ctx, service, proto, name)
}

// newTestRequest returns an HTTP request carrying the replacer that
// GetUpstreams relies on.
func newTestRequest() *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	return req.WithContext(context.WithValue(req.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))
}

// TestSRVUpstreamsSlowLookupDoesNotBlockOtherKeys is a regression test for the
// case where a slow SRV lookup for one key held the global cache lock across
// the DNS call, blocking lookups for every unrelated key. The slow lookup is
// held open on a channel while a second, independent key is looked up; the
// second lookup must complete quickly rather than waiting for the slow one.
func TestSRVUpstreamsSlowLookupDoesNotBlockOtherKeys(t *testing.T) {
	release := make(chan struct{})
	blockedEntered := make(chan struct{})

	resolver := &fakeSRVResolver{
		lookupSRV: func(_ context.Context, _, _, name string) (string, []*net.SRV, error) {
			switch name {
			case "slow.example.com":
				close(blockedEntered)
				<-release
				return "", []*net.SRV{{Target: "10.0.0.1", Port: 80}}, nil
			case "fast.example.com":
				return "", []*net.SRV{{Target: "10.0.0.2", Port: 80}}, nil
			default:
				return "", nil, fmt.Errorf("unexpected SRV lookup for %q", name)
			}
		},
	}

	slow := &SRVUpstreams{
		Name:     "slow.example.com",
		Refresh:  caddy.Duration(time.Minute),
		resolver: resolver,
		logger:   zap.NewNop(),
	}
	fast := &SRVUpstreams{
		Name:     "fast.example.com",
		Refresh:  caddy.Duration(time.Minute),
		resolver: resolver,
		logger:   zap.NewNop(),
	}

	// start from a clean cache so both keys are guaranteed to be a miss
	slow.ResetCache(nil)
	fast.ResetCache(nil)

	slowErr := make(chan error, 1)
	go func() {
		_, err := slow.GetUpstreams(newTestRequest())
		slowErr <- err
	}()

	// wait until the slow lookup is actually in flight before racing the fast one
	<-blockedEntered

	fastStart := time.Now()
	fastRes := make(chan struct {
		ups []*Upstream
		err error
	}, 1)
	go func() {
		ups, err := fast.GetUpstreams(newTestRequest())
		fastRes <- struct {
			ups []*Upstream
			err error
		}{ups, err}
	}()

	select {
	case res := <-fastRes:
		if res.err != nil {
			t.Fatalf("fast lookup errored: %v", res.err)
		}
		if len(res.ups) != 1 || res.ups[0].Dial != "10.0.0.2:80" {
			t.Fatalf("unexpected fast lookup result: %+v", res.ups)
		}
		if elapsed := time.Since(fastStart); elapsed > 500*time.Millisecond {
			t.Fatalf("fast lookup took %v; it should not be blocked by the slow lookup", elapsed)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("fast lookup was blocked behind the slow lookup")
	}

	// release the slow lookup and make sure it completes successfully
	close(release)
	if err := <-slowErr; err != nil {
		t.Fatalf("slow lookup errored: %v", err)
	}
}

// TestSRVUpstreamsResetCacheDuringLookup verifies that a lookup that is still
// in flight when ResetCache runs does not repopulate the cache afterwards
// (which would silently undo the reset).
func TestSRVUpstreamsResetCacheDuringLookup(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reset func(su *SRVUpstreams, req *http.Request) error
	}{
		{
			name: "full reset",
			reset: func(su *SRVUpstreams, _ *http.Request) error {
				return su.ResetCache(nil)
			},
		},
		{
			name: "targeted reset",
			reset: func(su *SRVUpstreams, req *http.Request) error {
				return su.ResetCache(req)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			release := make(chan struct{})
			entered := make(chan struct{})
			resolver := &fakeSRVResolver{
				lookupSRV: func(_ context.Context, _, _, _ string) (string, []*net.SRV, error) {
					close(entered)
					<-release
					return "", []*net.SRV{{Target: "10.0.0.1", Port: 80}}, nil
				},
			}
			su := &SRVUpstreams{
				Name:     "reset.example.com",
				Refresh:  caddy.Duration(time.Minute),
				resolver: resolver,
				logger:   zap.NewNop(),
			}
			su.ResetCache(nil)

			req := newTestRequest()
			done := make(chan error, 1)
			go func() {
				_, err := su.GetUpstreams(req)
				done <- err
			}()

			<-entered
			if err := tc.reset(su, req); err != nil {
				t.Fatalf("ResetCache: %v", err)
			}
			close(release)
			if err := <-done; err != nil {
				t.Fatalf("GetUpstreams: %v", err)
			}

			srvsMu.RLock()
			cached := srvs["reset.example.com"]
			srvsMu.RUnlock()
			if cached.isFresh() || len(cached.upstreams) != 0 {
				t.Fatal("stale in-flight lookup repopulated the cache after reset")
			}
		})
	}
}

// TestSRVUpstreamsResetCacheStartsNewFlight verifies that a request arriving
// after ResetCache starts its own lookup rather than joining the lookup that was
// already in flight when the reset happened, which would hand it back the very
// result the reset discarded.
func TestSRVUpstreamsResetCacheStartsNewFlight(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{})

	var mu sync.Mutex
	var lookups int
	resolver := &fakeSRVResolver{
		lookupSRV: func(_ context.Context, _, _, _ string) (string, []*net.SRV, error) {
			mu.Lock()
			lookups++
			n := lookups
			mu.Unlock()
			if n == 1 {
				close(entered)
				<-release
				return "", []*net.SRV{{Target: "10.0.0.1", Port: 80}}, nil
			}
			return "", []*net.SRV{{Target: "10.0.0.2", Port: 80}}, nil
		},
	}

	su := &SRVUpstreams{
		Name:     "flight.example.com",
		Refresh:  caddy.Duration(time.Minute),
		resolver: resolver,
		logger:   zap.NewNop(),
	}
	su.ResetCache(nil)

	firstErr := make(chan error, 1)
	go func() {
		_, err := su.GetUpstreams(newTestRequest())
		firstErr <- err
	}()

	// once the first lookup is in flight, discard its still-pending result
	<-entered
	if err := su.ResetCache(newTestRequest()); err != nil {
		t.Fatalf("ResetCache: %v", err)
	}

	second := make(chan struct {
		ups []*Upstream
		err error
	}, 1)
	go func() {
		ups, err := su.GetUpstreams(newTestRequest())
		second <- struct {
			ups []*Upstream
			err error
		}{ups, err}
	}()

	select {
	case res := <-second:
		if res.err != nil {
			t.Fatalf("post-reset lookup errored: %v", res.err)
		}
		if len(res.ups) != 1 || res.ups[0].Dial != "10.0.0.2:80" {
			t.Fatalf("post-reset request was served the pre-reset result: %+v", res.ups)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("post-reset request joined the pre-reset lookup instead of starting its own")
	}

	close(release)
	if err := <-firstErr; err != nil {
		t.Fatalf("first lookup errored: %v", err)
	}
}

// TestSRVUpstreamsStaleLookupDoesNotOverwriteNewer covers a lookup that is
// overtaken both by a reset and by a second, newer lookup: when the stale one
// finally finishes it must not write its result over the newer one. This is why
// the per-key generation counter is never removed once bumped -- recycling it
// back to zero lets the stale lookup's captured generation match again.
func TestSRVUpstreamsStaleLookupDoesNotOverwriteNewer(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{})

	var mu sync.Mutex
	var lookups int
	su := &SRVUpstreams{
		Name:    "stale.example.com",
		Refresh: caddy.Duration(time.Minute),
		resolver: &fakeSRVResolver{
			lookupSRV: func(context.Context, string, string, string) (string, []*net.SRV, error) {
				mu.Lock()
				lookups++
				n := lookups
				mu.Unlock()
				if n == 1 {
					close(entered)
					<-release
					return "", []*net.SRV{{Target: "10.0.0.1", Port: 80}}, nil
				}
				return "", []*net.SRV{{Target: "10.0.0.2", Port: 80}}, nil
			},
		},
		logger: zap.NewNop(),
	}
	su.ResetCache(nil)

	staleErr := make(chan error, 1)
	go func() {
		_, err := su.GetUpstreams(newTestRequest())
		staleErr <- err
	}()
	<-entered

	// discard the in-flight lookup's result, then let a newer lookup land
	if err := su.ResetCache(newTestRequest()); err != nil {
		t.Fatalf("ResetCache: %v", err)
	}
	newer := make(chan error, 1)
	go func() {
		_, err := su.GetUpstreams(newTestRequest())
		newer <- err
	}()
	select {
	case err := <-newer:
		if err != nil {
			t.Fatalf("newer lookup errored: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		close(release) // don't wedge the stale lookup's goroutine
		t.Fatal("newer lookup joined the stale in-flight lookup instead of starting its own")
	}

	// the stale lookup finishes last; its result is no longer wanted
	close(release)
	if err := <-staleErr; err != nil {
		t.Fatalf("stale lookup errored: %v", err)
	}

	srvsMu.RLock()
	cached := srvs["stale.example.com"]
	srvsMu.RUnlock()
	if len(cached.upstreams) != 1 || cached.upstreams[0].Dial != "10.0.0.2:80" {
		t.Fatalf("stale lookup overwrote the newer result: %+v", cached.upstreams)
	}
}

// fakeAResolver implements aResolver so tests can control the timing and
// results of A/AAAA lookups without a real DNS server.
type fakeAResolver struct {
	lookupIP func(ctx context.Context, network, host string) ([]net.IP, error)
}

func (f *fakeAResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	return f.lookupIP(ctx, network, host)
}

// testAUpstreams returns an AUpstreams restricted to IPv4 and backed by the
// given lookup function.
func testAUpstreams(name string, lookupIP func(ctx context.Context, network, host string) ([]net.IP, error)) *AUpstreams {
	ipv4, ipv6 := true, false
	return &AUpstreams{
		Name:     name,
		Port:     "80",
		Refresh:  caddy.Duration(time.Minute),
		Versions: &IPVersions{IPv4: &ipv4, IPv6: &ipv6},
		resolver: &fakeAResolver{lookupIP: lookupIP},
		logger:   zap.NewNop(),
	}
}

// TestAUpstreamsSlowLookupDoesNotBlockOtherKeys is the A/AAAA equivalent of
// TestSRVUpstreamsSlowLookupDoesNotBlockOtherKeys.
func TestAUpstreamsSlowLookupDoesNotBlockOtherKeys(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{})

	slow := testAUpstreams("slow.example.com", func(context.Context, string, string) ([]net.IP, error) {
		close(entered)
		<-release
		return []net.IP{net.IPv4(10, 0, 0, 1)}, nil
	})
	fast := testAUpstreams("fast.example.com", func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{net.IPv4(10, 0, 0, 2)}, nil
	})

	slow.ResetCache(nil)
	fast.ResetCache(nil)

	slowErr := make(chan error, 1)
	go func() {
		_, err := slow.GetUpstreams(newTestRequest())
		slowErr <- err
	}()

	<-entered

	fastStart := time.Now()
	fastRes := make(chan struct {
		ups []*Upstream
		err error
	}, 1)
	go func() {
		ups, err := fast.GetUpstreams(newTestRequest())
		fastRes <- struct {
			ups []*Upstream
			err error
		}{ups, err}
	}()

	select {
	case res := <-fastRes:
		if res.err != nil {
			t.Fatalf("fast lookup errored: %v", res.err)
		}
		if len(res.ups) != 1 || res.ups[0].Dial != "10.0.0.2:80" {
			t.Fatalf("unexpected fast lookup result: %+v", res.ups)
		}
		if elapsed := time.Since(fastStart); elapsed > 500*time.Millisecond {
			t.Fatalf("fast lookup took %v; it should not be blocked by the slow lookup", elapsed)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("fast lookup was blocked behind the slow lookup")
	}

	close(release)
	if err := <-slowErr; err != nil {
		t.Fatalf("slow lookup errored: %v", err)
	}
}

// TestAUpstreamsResetCacheDuringLookup verifies the A/AAAA equivalent of the
// SRV reset-during-lookup behavior.
func TestAUpstreamsResetCacheDuringLookup(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reset func(au *AUpstreams, req *http.Request) error
	}{
		{
			name: "full reset",
			reset: func(au *AUpstreams, _ *http.Request) error {
				return au.ResetCache(nil)
			},
		},
		{
			name: "targeted reset",
			reset: func(au *AUpstreams, req *http.Request) error {
				return au.ResetCache(req)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			release := make(chan struct{})
			entered := make(chan struct{})

			au := testAUpstreams("reset.example.com", func(context.Context, string, string) ([]net.IP, error) {
				close(entered)
				<-release
				return []net.IP{net.IPv4(10, 0, 0, 1)}, nil
			})
			au.ResetCache(nil)

			req := newTestRequest()
			done := make(chan error, 1)
			go func() {
				_, err := au.GetUpstreams(req)
				done <- err
			}()

			<-entered
			if err := tc.reset(au, req); err != nil {
				t.Fatalf("ResetCache: %v", err)
			}
			close(release)
			if err := <-done; err != nil {
				t.Fatalf("GetUpstreams: %v", err)
			}

			key := au.String() + resolveIpVersion(au.Versions)
			aAaaaMu.RLock()
			cached := aAaaa[key]
			aAaaaMu.RUnlock()
			if cached.isFresh() || len(cached.upstreams) != 0 {
				t.Fatal("stale in-flight lookup repopulated the cache after reset")
			}
		})
	}
}

// TestAUpstreamsResetCacheStartsNewFlight is the A/AAAA equivalent of
// TestSRVUpstreamsResetCacheStartsNewFlight.
func TestAUpstreamsResetCacheStartsNewFlight(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{})

	var mu sync.Mutex
	var lookups int
	au := testAUpstreams("flight.example.com", func(context.Context, string, string) ([]net.IP, error) {
		mu.Lock()
		lookups++
		n := lookups
		mu.Unlock()
		if n == 1 {
			close(entered)
			<-release
			return []net.IP{net.IPv4(10, 0, 0, 1)}, nil
		}
		return []net.IP{net.IPv4(10, 0, 0, 2)}, nil
	})
	au.ResetCache(nil)

	firstErr := make(chan error, 1)
	go func() {
		_, err := au.GetUpstreams(newTestRequest())
		firstErr <- err
	}()

	// once the first lookup is in flight, discard its still-pending result
	<-entered
	if err := au.ResetCache(newTestRequest()); err != nil {
		t.Fatalf("ResetCache: %v", err)
	}

	second := make(chan struct {
		ups []*Upstream
		err error
	}, 1)
	go func() {
		ups, err := au.GetUpstreams(newTestRequest())
		second <- struct {
			ups []*Upstream
			err error
		}{ups, err}
	}()

	select {
	case res := <-second:
		if res.err != nil {
			t.Fatalf("post-reset lookup errored: %v", res.err)
		}
		if len(res.ups) != 1 || res.ups[0].Dial != "10.0.0.2:80" {
			t.Fatalf("post-reset request was served the pre-reset result: %+v", res.ups)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("post-reset request joined the pre-reset lookup instead of starting its own")
	}

	close(release)
	if err := <-firstErr; err != nil {
		t.Fatalf("first lookup errored: %v", err)
	}
}

// TestAUpstreamsStaleLookupDoesNotOverwriteNewer is the A/AAAA equivalent of
// TestSRVUpstreamsStaleLookupDoesNotOverwriteNewer.
func TestAUpstreamsStaleLookupDoesNotOverwriteNewer(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{})

	var mu sync.Mutex
	var lookups int
	au := testAUpstreams("stale.example.com", func(context.Context, string, string) ([]net.IP, error) {
		mu.Lock()
		lookups++
		n := lookups
		mu.Unlock()
		if n == 1 {
			close(entered)
			<-release
			return []net.IP{net.IPv4(10, 0, 0, 1)}, nil
		}
		return []net.IP{net.IPv4(10, 0, 0, 2)}, nil
	})
	au.ResetCache(nil)

	staleErr := make(chan error, 1)
	go func() {
		_, err := au.GetUpstreams(newTestRequest())
		staleErr <- err
	}()
	<-entered

	// discard the in-flight lookup's result, then let a newer lookup land
	if err := au.ResetCache(newTestRequest()); err != nil {
		t.Fatalf("ResetCache: %v", err)
	}
	newer := make(chan error, 1)
	go func() {
		_, err := au.GetUpstreams(newTestRequest())
		newer <- err
	}()
	select {
	case err := <-newer:
		if err != nil {
			t.Fatalf("newer lookup errored: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		close(release) // don't wedge the stale lookup's goroutine
		t.Fatal("newer lookup joined the stale in-flight lookup instead of starting its own")
	}

	// the stale lookup finishes last; its result is no longer wanted
	close(release)
	if err := <-staleErr; err != nil {
		t.Fatalf("stale lookup errored: %v", err)
	}

	key := au.String() + resolveIpVersion(au.Versions)
	aAaaaMu.RLock()
	cached := aAaaa[key]
	aAaaaMu.RUnlock()
	if len(cached.upstreams) != 1 || cached.upstreams[0].Dial != "10.0.0.2:80" {
		t.Fatalf("stale lookup overwrote the newer result: %+v", cached.upstreams)
	}
}

// TestSRVUpstreamsLeaderCancellationDoesNotAffectOtherWaiters is a
// regression test for the shared lookup being tied to whichever request
// happened to trigger it. It cancels the request that started the
// singleflight lookup while a second, independent request is still waiting
// on the same flight, and checks two things: the cancelled request returns
// promptly with its own context error instead of waiting for the lookup,
// and the other waiter still gets a correct result once the lookup
// completes, unaffected by the leader's cancellation.
func TestSRVUpstreamsLeaderCancellationDoesNotAffectOtherWaiters(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{})

	resolver := &fakeSRVResolver{
		lookupSRV: func(ctx context.Context, _, _, _ string) (string, []*net.SRV, error) {
			close(entered)
			select {
			case <-release:
				return "", []*net.SRV{{Target: "10.0.0.1", Port: 80}}, nil
			case <-ctx.Done():
				// only reached if the lookup is still tied to the leader's
				// context; that's the bug this test guards against
				return "", nil, ctx.Err()
			}
		},
	}

	su := &SRVUpstreams{
		Name:     "leader-cancel.example.com",
		Refresh:  caddy.Duration(time.Minute),
		resolver: resolver,
		logger:   zap.NewNop(),
	}
	su.ResetCache(nil)

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderReq := httptest.NewRequest(http.MethodGet, "http://example.com/", nil).
		WithContext(context.WithValue(leaderCtx, caddy.ReplacerCtxKey, caddy.NewReplacer()))

	leaderDone := make(chan error, 1)
	go func() {
		_, err := su.GetUpstreams(leaderReq)
		leaderDone <- err
	}()

	// wait until the lookup the leader triggered is actually running
	<-entered

	// a second, independent request for the same key joins the same flight
	waiterDone := make(chan struct {
		ups []*Upstream
		err error
	}, 1)
	go func() {
		ups, err := su.GetUpstreams(newTestRequest())
		waiterDone <- struct {
			ups []*Upstream
			err error
		}{ups, err}
	}()

	// give the waiter a moment to actually join the leader's flight
	time.Sleep(50 * time.Millisecond)

	cancelLeader()
	select {
	case err := <-leaderDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected leader to return context.Canceled, got %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("leader did not return promptly after its own context was cancelled")
	}

	// the lookup must still be running for the waiter, unaffected by the
	// leader's cancellation
	close(release)
	select {
	case res := <-waiterDone:
		if res.err != nil {
			t.Fatalf("waiter errored: %v", res.err)
		}
		if len(res.ups) != 1 || res.ups[0].Dial != "10.0.0.1:80" {
			t.Fatalf("unexpected waiter result: %+v", res.ups)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("waiter never received a result after the lookup completed")
	}
}

// TestAUpstreamsLeaderCancellationDoesNotAffectOtherWaiters is the A/AAAA
// equivalent of TestSRVUpstreamsLeaderCancellationDoesNotAffectOtherWaiters.
func TestAUpstreamsLeaderCancellationDoesNotAffectOtherWaiters(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{})

	au := testAUpstreams("leader-cancel.example.com", func(ctx context.Context, _, _ string) ([]net.IP, error) {
		close(entered)
		select {
		case <-release:
			return []net.IP{net.IPv4(10, 0, 0, 1)}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	au.ResetCache(nil)

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderReq := httptest.NewRequest(http.MethodGet, "http://example.com/", nil).
		WithContext(context.WithValue(leaderCtx, caddy.ReplacerCtxKey, caddy.NewReplacer()))

	leaderDone := make(chan error, 1)
	go func() {
		_, err := au.GetUpstreams(leaderReq)
		leaderDone <- err
	}()

	<-entered

	waiterDone := make(chan struct {
		ups []*Upstream
		err error
	}, 1)
	go func() {
		ups, err := au.GetUpstreams(newTestRequest())
		waiterDone <- struct {
			ups []*Upstream
			err error
		}{ups, err}
	}()

	time.Sleep(50 * time.Millisecond)

	cancelLeader()
	select {
	case err := <-leaderDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected leader to return context.Canceled, got %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("leader did not return promptly after its own context was cancelled")
	}

	close(release)
	select {
	case res := <-waiterDone:
		if res.err != nil {
			t.Fatalf("waiter errored: %v", res.err)
		}
		if len(res.ups) != 1 || res.ups[0].Dial != "10.0.0.1:80" {
			t.Fatalf("unexpected waiter result: %+v", res.ups)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("waiter never received a result after the lookup completed")
	}
}

// saturateSeq keeps the keys used by saturateLookupGate distinct between
// calls, so a later call can't be served from the cache the earlier one filled.
var saturateSeq atomic.Uint64

// saturateLookupGate fills every slot on the shared lookup gate with SRV
// lookups that stall inside the resolver, and returns the func that releases
// them and waits for them to finish.
func saturateLookupGate(t *testing.T) func() {
	t.Helper()

	seq := saturateSeq.Add(1)
	release := make(chan struct{})
	running := make(chan struct{}, upstreamsMaxLookups)
	resolver := &fakeSRVResolver{
		lookupSRV: func(context.Context, string, string, string) (string, []*net.SRV, error) {
			running <- struct{}{}
			<-release
			return "", []*net.SRV{{Target: "10.0.0.1", Port: 80}}, nil
		},
	}

	var wg sync.WaitGroup
	for i := range upstreamsMaxLookups {
		su := &SRVUpstreams{
			Name:     fmt.Sprintf("saturate-%d-%d.example.com", seq, i),
			Refresh:  caddy.Duration(time.Minute),
			resolver: resolver,
			logger:   zap.NewNop(),
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := su.GetUpstreams(newTestRequest()); err != nil {
				t.Errorf("saturating lookup errored: %v", err)
			}
		}()
	}

	unsaturate := func() {
		close(release)
		wg.Wait()
	}

	// the gate is full once every one of those is inside the resolver
	for range upstreamsMaxLookups {
		select {
		case <-running:
		case <-time.After(10 * time.Second):
			unsaturate()
			t.Fatal("lookups never filled the gate")
		}
	}
	return unsaturate
}

type upstreamsResult struct {
	ups []*Upstream
	err error
}

// TestLookupGate covers the gate on its own: it hands out no more than
// maxRunning slots, sheds once the wait queue is full, lets a queued caller be
// cancelled by its own context, and recovers as slots are released.
func TestLookupGate(t *testing.T) {
	gate := newLookupGate(2, 1)

	// saturation: both slots go out, so the next caller has to wait
	for i := range 2 {
		if err := gate.acquire(context.Background()); err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
	}

	waiterCtx, cancelWaiter := context.WithCancel(context.Background())
	waiting := make(chan error, 1)
	go func() { waiting <- gate.acquire(waiterCtx) }()

	// wait until that caller is actually queued
	deadline := time.Now().Add(10 * time.Second)
	for gate.pending.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("waiter never queued")
		}
		time.Sleep(time.Millisecond)
	}

	// the queue is full now, so anyone else is shed instead of parked
	if err := gate.acquire(context.Background()); !errors.Is(err, errTooManyLookups) {
		t.Fatalf("expected errTooManyLookups once the queue was full, got %v", err)
	}

	// cancellation: the queued caller leaves on its own context, and the
	// queue accounting has to come back with it
	cancelWaiter()
	select {
	case err := <-waiting:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected the queued caller to return context.Canceled, got %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("queued caller did not return after its context was cancelled")
	}
	if p := gate.pending.Load(); p != 0 {
		t.Fatalf("expected the queue to drain back to 0, got %d", p)
	}

	// recovery: a released slot is usable again
	gate.release()
	if err := gate.acquire(context.Background()); err != nil {
		t.Fatalf("expected to reuse the released slot, got %v", err)
	}
	gate.release()
	gate.release()
}

// TestLookupGateStrayReleaseDoesNotBlock pins the acquire/release rule. a
// release with nothing held is a bug, but it must return instead of hanging
// the goroutine, since it runs inside a singleflight call.
func TestLookupGateStrayReleaseDoesNotBlock(t *testing.T) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		newLookupGate(2, 1).release()
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("a release with nothing held blocked instead of returning")
	}
}

// TestSRVUpstreamsLookupsAreBounded checks that the gate is wired into the SRV
// lookup path. Distinct keys each start a lookup of their own, so without a
// shared bound a stream of them would be unbounded concurrent resolver work.
// While the gate is saturated a further key must not reach the resolver at all,
// and it must resolve normally once slots free up.
func TestSRVUpstreamsLookupsAreBounded(t *testing.T) {
	var lookups atomic.Int32
	su := &SRVUpstreams{
		Name:    "bounded.example.com",
		Refresh: caddy.Duration(time.Minute),
		resolver: &fakeSRVResolver{
			lookupSRV: func(context.Context, string, string, string) (string, []*net.SRV, error) {
				lookups.Add(1)
				return "", []*net.SRV{{Target: "10.0.0.2", Port: 80}}, nil
			},
		},
		logger: zap.NewNop(),
	}
	su.ResetCache(nil)

	unsaturate := saturateLookupGate(t)

	done := make(chan upstreamsResult, 1)
	go func() {
		ups, err := su.GetUpstreams(newTestRequest())
		done <- upstreamsResult{ups, err}
	}()

	// saturation: the lookup waits for a slot instead of running
	select {
	case res := <-done:
		unsaturate()
		t.Fatalf("lookup completed while the gate was saturated: %+v (err %v)", res.ups, res.err)
	case <-time.After(100 * time.Millisecond):
	}
	if n := lookups.Load(); n != 0 {
		unsaturate()
		t.Fatalf("expected the resolver to be untouched while saturated, saw %d lookups", n)
	}

	// recovery: with slots back, the queued lookup runs and returns
	unsaturate()
	select {
	case res := <-done:
		if res.err != nil {
			t.Fatalf("queued lookup errored: %v", res.err)
		}
		if len(res.ups) != 1 || res.ups[0].Dial != "10.0.0.2:80" {
			t.Fatalf("unexpected upstreams: %+v", res.ups)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("queued lookup never ran after slots freed up")
	}
}

// TestSRVUpstreamsQueuedLookupStillCancels checks that waiting for a slot
// doesn't cost a request its own cancellation: it returns as soon as its
// context is cancelled, even though the lookup it started is still queued.
func TestSRVUpstreamsQueuedLookupStillCancels(t *testing.T) {
	su := &SRVUpstreams{
		Name:    "queued.example.com",
		Refresh: caddy.Duration(time.Minute),
		resolver: &fakeSRVResolver{
			lookupSRV: func(context.Context, string, string, string) (string, []*net.SRV, error) {
				return "", []*net.SRV{{Target: "10.0.0.2", Port: 80}}, nil
			},
		},
		logger: zap.NewNop(),
	}
	su.ResetCache(nil)

	unsaturate := saturateLookupGate(t)

	reqCtx, cancelReq := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil).
		WithContext(context.WithValue(reqCtx, caddy.ReplacerCtxKey, caddy.NewReplacer()))

	queued := make(chan error, 1)
	go func() {
		_, err := su.GetUpstreams(req)
		queued <- err
	}()

	// give the lookup a moment to park on the gate
	time.Sleep(50 * time.Millisecond)

	cancelReq()
	select {
	case err := <-queued:
		if !errors.Is(err, context.Canceled) {
			unsaturate()
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(10 * time.Second):
		unsaturate()
		t.Fatal("queued request did not return after its context was cancelled")
	}

	// the lookup itself outlives the request that started it, so let it
	// finish before leaving, and confirm the key still resolves
	unsaturate()
	if _, err := su.GetUpstreams(newTestRequest()); err != nil {
		t.Fatalf("key did not resolve after the queued request was cancelled: %v", err)
	}
}

// TestAUpstreamsLookupsAreBounded is the A/AAAA equivalent of
// TestSRVUpstreamsLookupsAreBounded. The gate is shared, so SRV lookups are
// what saturate it here.
func TestAUpstreamsLookupsAreBounded(t *testing.T) {
	var lookups atomic.Int32
	au := testAUpstreams("bounded.example.com", func(context.Context, string, string) ([]net.IP, error) {
		lookups.Add(1)
		return []net.IP{net.IPv4(10, 0, 0, 2)}, nil
	})
	au.ResetCache(nil)

	unsaturate := saturateLookupGate(t)

	done := make(chan upstreamsResult, 1)
	go func() {
		ups, err := au.GetUpstreams(newTestRequest())
		done <- upstreamsResult{ups, err}
	}()

	select {
	case res := <-done:
		unsaturate()
		t.Fatalf("lookup completed while the gate was saturated: %+v (err %v)", res.ups, res.err)
	case <-time.After(100 * time.Millisecond):
	}
	if n := lookups.Load(); n != 0 {
		unsaturate()
		t.Fatalf("expected the resolver to be untouched while saturated, saw %d lookups", n)
	}

	unsaturate()
	select {
	case res := <-done:
		if res.err != nil {
			t.Fatalf("queued lookup errored: %v", res.err)
		}
		if len(res.ups) != 1 || res.ups[0].Dial != "10.0.0.2:80" {
			t.Fatalf("unexpected upstreams: %+v", res.ups)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("queued lookup never ran after slots freed up")
	}
}

// installSheddingGate swaps in a gate with no free slot and no room to queue,
// so every lookup during the test is shed right away. puts the real one back
// at the end.
func installSheddingGate(t *testing.T) {
	t.Helper()

	previous := upstreamsLookups
	gate := newLookupGate(1, 0)
	if err := gate.acquire(context.Background()); err != nil {
		t.Fatalf("priming the shedding gate: %v", err)
	}
	upstreamsLookups = gate
	t.Cleanup(func() { upstreamsLookups = previous })
}

// newStaleSRVUpstreams returns an SRV source with a cached entry that's
// already stale, plus a count of resolver lookups so far.
func newStaleSRVUpstreams(t *testing.T, name string, gracePeriod time.Duration) (*SRVUpstreams, *atomic.Int32) {
	t.Helper()

	var lookups atomic.Int32
	su := &SRVUpstreams{
		Name:        name,
		Refresh:     caddy.Duration(time.Millisecond),
		GracePeriod: caddy.Duration(gracePeriod),
		resolver: &fakeSRVResolver{
			lookupSRV: func(context.Context, string, string, string) (string, []*net.SRV, error) {
				lookups.Add(1)
				return "", []*net.SRV{{Target: "10.0.0.5", Port: 80}}, nil
			},
		},
		logger: zap.NewNop(),
	}
	su.ResetCache(nil)

	// fill the cache, then let it age past refresh so the next request
	// has to try a lookup
	if _, err := su.GetUpstreams(newTestRequest()); err != nil {
		t.Fatalf("priming the cache: %v", err)
	}
	if n := lookups.Load(); n != 1 {
		t.Fatalf("expected exactly one priming lookup, saw %d", n)
	}
	time.Sleep(10 * time.Millisecond)

	return su, &lookups
}

// TestSRVUpstreamsShedServesStale checks that shedding still honors the grace
// period. a request that can't get a slot but has a stale entry should get
// those upstreams, not an error.
func TestSRVUpstreamsShedServesStale(t *testing.T) {
	su, lookups := newStaleSRVUpstreams(t, "shed-stale.example.com", time.Minute)

	installSheddingGate(t)

	ups, err := su.GetUpstreams(newTestRequest())
	if err != nil {
		t.Fatalf("expected the stale cache to be served when shed, got %v", err)
	}
	if len(ups) != 1 || ups[0].Dial != "10.0.0.5:80" {
		t.Fatalf("unexpected upstreams: %+v", ups)
	}
	if n := lookups.Load(); n != 1 {
		t.Fatalf("expected the resolver to be untouched while shed, saw %d lookups", n)
	}
}

// TestSRVUpstreamsShedErrors covers when serving stale isn't possible, so
// no grace period or nothing cached yet.
func TestSRVUpstreamsShedErrors(t *testing.T) {
	t.Run("no grace period", func(t *testing.T) {
		su, _ := newStaleSRVUpstreams(t, "shed-nograce.example.com", 0)

		installSheddingGate(t)

		if _, err := su.GetUpstreams(newTestRequest()); !errors.Is(err, errTooManyLookups) {
			t.Fatalf("expected errTooManyLookups without a grace period, got %v", err)
		}
	})

	t.Run("nothing cached", func(t *testing.T) {
		su := &SRVUpstreams{
			Name:        "shed-uncached.example.com",
			Refresh:     caddy.Duration(time.Minute),
			GracePeriod: caddy.Duration(time.Minute),
			resolver: &fakeSRVResolver{
				lookupSRV: func(context.Context, string, string, string) (string, []*net.SRV, error) {
					t.Error("resolver reached while the gate was shedding")
					return "", nil, nil
				},
			},
			logger: zap.NewNop(),
		}
		su.ResetCache(nil)

		installSheddingGate(t)

		// a grace period doesn't help with nothing to fall back on
		if _, err := su.GetUpstreams(newTestRequest()); !errors.Is(err, errTooManyLookups) {
			t.Fatalf("expected errTooManyLookups with an empty cache, got %v", err)
		}
	})
}

// TestAUpstreamsShedErrors checks the A side. no grace period there, so a
// shed lookup has to fail.
func TestAUpstreamsShedErrors(t *testing.T) {
	au := testAUpstreams("shed.example.com", func(context.Context, string, string) ([]net.IP, error) {
		t.Error("resolver reached while the gate was shedding")
		return nil, nil
	})
	au.ResetCache(nil)

	installSheddingGate(t)

	if _, err := au.GetUpstreams(newTestRequest()); !errors.Is(err, errTooManyLookups) {
		t.Fatalf("expected errTooManyLookups, got %v", err)
	}
}
