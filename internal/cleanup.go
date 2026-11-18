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
	"sync"
	"sync/atomic"
	"time"
)

// Cleanup coordinates holds on a cleanup callback and tracks retired callbacks
// for process exit. Use NewCleanup to construct one; it must not be copied.
type Cleanup struct {
	mu        sync.Mutex
	cleanup   func()
	callbacks []func()
	holds     int
	retired   bool
	cleaning  bool
	running   int // the cleanup pass and any in-flight late callbacks
	done      chan struct{}
}

// CleanupScope groups holds acquired through the context of a module load.
// Its state is protected by the owning Cleanup's mutex.
type CleanupScope struct {
	holds     int
	failed    bool
	onFailure func()
	timer     *time.Timer
}

// NewCleanup returns a coordinator for cleanup, which runs once after retirement
// and release of all holds. The callback runs synchronously without locks held.
func NewCleanup(cleanup func()) *Cleanup {
	return &Cleanup{cleanup: cleanup, done: make(chan struct{})}
}

// Add registers a callback to run in registration order before the cleanup
// function. Once cleanup starts, Add runs the callback synchronously in the
// caller and tracks it if the lifecycle is still active. Callbacks run without
// locks held.
func (c *Cleanup) Add(callback func()) {
	c.mu.Lock()
	if !c.cleaning {
		c.callbacks = append(c.callbacks, callback)
		c.mu.Unlock()
		return
	}
	tracked := c.running > 0
	if tracked {
		c.running++
	}
	c.mu.Unlock()
	if tracked {
		defer c.finishWork()
	}
	callback()
}

// Acquire retains cleanup until the returned idempotent release is called.
// It rejects retired coordinators and canceled contexts. A nil coordinator
// returns a no-op release for contexts without a cleanup lifecycle.
func (c *Cleanup) Acquire(ctx context.Context) (func(), bool) {
	return c.AcquireScoped(ctx, nil)
}

// AcquireScoped retains cleanup and associates the hold with scope when set.
func (c *Cleanup) AcquireScoped(ctx context.Context, scope *CleanupScope) (func(), bool) {
	if c == nil {
		return func() {}, ctx == nil || ctx.Err() == nil
	}
	c.mu.Lock()
	if c.retired || ctx.Err() != nil || (scope != nil && scope.failed) {
		c.mu.Unlock()
		return func() {}, false
	}
	c.holds++
	if scope != nil {
		scope.holds++
	}
	c.mu.Unlock()
	var released atomic.Bool
	return func() {
		if released.CompareAndSwap(false, true) {
			c.release(scope)
		}
	}, true
}

func (c *Cleanup) release(scope *CleanupScope) {
	c.mu.Lock()
	if scope != nil {
		scope.holds--
		if scope.failed {
			ready := scope.holds == 0
			c.mu.Unlock()
			if ready {
				c.finishFailedCleanup(scope)
			}
			return
		}
	}
	c.holds--
	clean := c.reserveCleanup()
	c.mu.Unlock()
	if clean {
		c.clean()
	}
}

// DeferFailedCleanup closes scope to new holds. It returns true if cleanup will
// run after the scoped holds release or timeout expires. Otherwise the caller
// runs cleanup synchronously.
func (c *Cleanup) DeferFailedCleanup(scope *CleanupScope, timeout time.Duration, cleanup func()) bool {
	if c == nil || scope == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	scope.failed = true
	if scope.holds == 0 {
		return false
	}
	// Keep one configuration hold until the failed module finishes cleanup.
	c.holds -= scope.holds - 1
	scope.onFailure = cleanup
	scope.timer = time.AfterFunc(timeout, func() { c.finishFailedCleanup(scope) })
	return true
}

func (c *Cleanup) finishFailedCleanup(scope *CleanupScope) {
	c.mu.Lock()
	cleanup := scope.onFailure
	if cleanup == nil {
		c.mu.Unlock()
		return
	}
	scope.onFailure = nil
	scope.timer.Stop()
	scope.timer = nil
	c.mu.Unlock()
	defer c.release(nil)
	cleanup()
}

// Retire prevents new holds and runs cleanup once the existing holds release.
// It does not cancel the caller's context and is safe to call more than once.
func (c *Cleanup) Retire() {
	c.mu.Lock()
	if !c.retired {
		c.retired = true
		retiredCleanups.Lock()
		retiredCleanups.pending[c] = struct{}{}
		retiredCleanups.Unlock()
	}
	clean := c.reserveCleanup()
	c.mu.Unlock()
	if clean {
		c.clean()
	}
}

// reserveCleanup is called with mu held. Once reserved, no new holds can be
// acquired and all work protected by previous holds has finished.
func (c *Cleanup) reserveCleanup() bool {
	if !c.retired || c.holds != 0 || c.cleaning {
		return false
	}
	c.cleaning = true
	c.running = 1
	return true
}

func (c *Cleanup) clean() {
	c.mu.Lock()
	callbacks := c.callbacks
	c.callbacks = nil
	c.mu.Unlock()
	for _, callback := range callbacks {
		callback()
	}
	c.cleanup()
	c.finishWork()
}

func (c *Cleanup) finishWork() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.running--
	if c.running != 0 {
		return
	}
	retiredCleanups.Lock()
	close(c.done)
	delete(retiredCleanups.pending, c)
	retiredCleanups.Unlock()
}

var retiredCleanups = struct {
	sync.Mutex
	pending map[*Cleanup]struct{}
}{pending: make(map[*Cleanup]struct{})}

// WaitForCleanup waits until all explicitly retired lifecycles finish,
// including lifecycles retired by other cleanup callbacks. The caller's context
// bounds the wait even if a cleanup callback is blocked.
func WaitForCleanup(ctx context.Context) error {
	for {
		retiredCleanups.Lock()
		pending := make([]<-chan struct{}, 0, len(retiredCleanups.pending))
		for c := range retiredCleanups.pending {
			pending = append(pending, c.done)
		}
		retiredCleanups.Unlock()
		if len(pending) == 0 {
			return nil
		}
		for _, done := range pending {
			select {
			case <-done:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}
