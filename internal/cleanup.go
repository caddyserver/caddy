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
	done      chan struct{}
}

// NewCleanup returns a coordinator for cleanup, which runs once after retirement
// and release of all holds. The callback runs synchronously without locks held.
func NewCleanup(cleanup func()) *Cleanup {
	return &Cleanup{cleanup: cleanup, done: make(chan struct{})}
}

// Add registers a callback to run before the constructor's cleanup function.
// Callbacks run in registration order, synchronously without locks held.
// Registration remains possible while a retired coordinator still has holds.
// Once cleanup starts, Add returns false without registering or running callback.
func (c *Cleanup) Add(callback func()) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cleaning {
		return false
	}
	c.callbacks = append(c.callbacks, callback)
	return true
}

// Acquire retains cleanup until the returned idempotent release is called.
// It rejects retired coordinators and canceled contexts. A nil coordinator
// returns a no-op release for contexts without a cleanup lifecycle.
func (c *Cleanup) Acquire(ctx context.Context) (func(), bool) {
	if c == nil {
		return func() {}, ctx == nil || ctx.Err() == nil
	}
	c.mu.Lock()
	if c.retired || ctx.Err() != nil {
		c.mu.Unlock()
		return func() {}, false
	}
	c.holds++
	c.mu.Unlock()
	var released atomic.Bool
	return func() {
		if released.CompareAndSwap(false, true) {
			c.mu.Lock()
			c.holds--
			clean := c.reserveCleanup()
			c.mu.Unlock()
			if clean {
				c.clean()
			}
		}
	}, true
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
// including lifecycles retired by other cleanup callbacks. Cleanup is performed
// by Retire or the final release, never by the waiter, so ctx can bound even a
// blocked cleanup callback.
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
