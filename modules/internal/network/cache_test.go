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
	"testing"
	"time"

	"go.uber.org/zap"
)

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

func TestEvictedResetMarkerRejectsStaleLookup(t *testing.T) {
	c := newCache("test")
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)

	go func() {
		_, err := c.get(context.Background(), "key", time.Minute, 0, zap.NewNop(), func(context.Context) ([]Target, error) {
			close(started)
			<-release
			return []Target{{Host: "old.example"}}, nil
		})
		done <- err
	}()
	<-started

	c.reset("key")
	c.mu.Lock()
	delete(c.entries, "key")
	c.mu.Unlock()
	close(release)

	if err := <-done; err != nil {
		t.Fatal(err)
	}
	c.mu.RLock()
	_, exists := c.entries["key"]
	c.mu.RUnlock()
	if exists {
		t.Fatal("lookup repopulated an entry after its reset marker was evicted")
	}
}

func TestDifferentGracePoliciesDoNotShareLookup(t *testing.T) {
	for _, tc := range []struct {
		name       string
		graceFirst bool
	}{
		{name: "no grace first"},
		{name: "grace first", graceFirst: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newCache("test")
			c.entries["key"] = cacheEntry{
				refresh:   time.Minute,
				freshness: time.Now().Add(-time.Hour),
				targets:   []Target{{Host: "stale.example"}},
			}

			started := make(chan struct{}, 2)
			release := make(chan struct{})
			lookup := func(context.Context) ([]Target, error) {
				started <- struct{}{}
				<-release
				return nil, errors.New("lookup failed")
			}
			type result struct {
				targets []Target
				err     error
			}
			start := func(grace time.Duration) <-chan result {
				ch := make(chan result, 1)
				go func() {
					targets, err := c.get(context.Background(), "key", time.Minute, grace, zap.NewNop(), lookup)
					ch <- result{targets, err}
				}()
				return ch
			}

			firstGrace := time.Duration(0)
			secondGrace := time.Minute
			if tc.graceFirst {
				firstGrace, secondGrace = secondGrace, firstGrace
			}
			first := start(firstGrace)
			<-started
			second := start(secondGrace)
			select {
			case <-started:
			case <-time.After(time.Second):
				close(release)
				<-first
				<-second
				t.Fatalf("different grace policies shared one lookup")
			}
			close(release)

			firstResult := <-first
			secondResult := <-second
			if tc.graceFirst {
				firstResult, secondResult = secondResult, firstResult
			}
			if firstResult.err == nil {
				t.Fatal("caller without grace did not receive the lookup error")
			}
			if secondResult.err != nil || len(secondResult.targets) != 1 || secondResult.targets[0].Host != "stale.example" {
				t.Fatalf("caller with grace: targets = %v, err = %v", secondResult.targets, secondResult.err)
			}
		})
	}
}
