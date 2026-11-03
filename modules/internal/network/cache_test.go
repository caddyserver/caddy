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
