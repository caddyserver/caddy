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

package internal

import (
	"context"
	"sync/atomic"
	"testing"
)

func TestCleanupRegistrationAndCompletion(t *testing.T) {
	var cleaned atomic.Int32
	cleanup := NewCleanup(func() { cleaned.Add(1) })
	release, ok := cleanup.Acquire(context.Background())
	if !ok {
		t.Fatal("acquisition failed before retirement")
	}
	t.Cleanup(release)
	cleanup.Retire()
	retiredCleanups.Lock()
	_, pending := retiredCleanups.pending[cleanup]
	retiredCleanups.Unlock()
	if !pending || cleaned.Load() != 0 {
		t.Fatal("held retirement was not registered without cleaning")
	}
	release()
	release()
	cleanup.Retire()
	lateRelease, ok := cleanup.Acquire(context.Background())
	lateRelease()
	retiredCleanups.Lock()
	_, pending = retiredCleanups.pending[cleanup]
	retiredCleanups.Unlock()
	if pending || cleaned.Load() != 1 || ok {
		t.Fatal("completed cleanup was repeated, retained or acquired")
	}
}

func TestCleanupCanceledAcquisition(t *testing.T) {
	var cleaned atomic.Int32
	cleanup := NewCleanup(func() { cleaned.Add(1) })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	release, ok := cleanup.Acquire(ctx)
	release()
	if ok || cleaned.Load() != 0 {
		t.Fatal("canceled acquisition retained or retired cleanup")
	}
	cleanup.Retire()
	if cleaned.Load() != 1 {
		t.Fatal("rejected acquisition prevented synchronous cleanup")
	}

	var absent *Cleanup
	release, ok = absent.Acquire(nil)
	release()
	if !ok {
		t.Fatal("missing lifecycle rejected a context without cancellation")
	}
	release, ok = absent.Acquire(ctx)
	release()
	if ok {
		t.Fatal("missing lifecycle accepted a canceled context")
	}
}
