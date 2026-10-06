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

package caddy

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
)

// HoldCleanup delays Cleanup of modules loaded by ctx until the returned
// release function has been called. Acquire the hold before cancellation;
// acquisition after cancellation does nothing. All holds must be released,
// including on error paths. Release is safe to call more than once.
// The final release may run module Cleanup methods synchronously, so release
// only after the work that needs those modules has finished.
//
// A hold does not delay context cancellation or OnCancel callbacks. Copies
// of ctx, including those returned by WithValue, share the same holds.
// Module cleanup still requires calling the cancel function from NewContext
// or NewContextWithCause; cancellation of a parent alone does not trigger it.
//
// EXPERIMENTAL: This API is subject to change.
func (ctx Context) HoldCleanup() func() {
	release, _ := ctx.cleanup.acquire(ctx.Context)
	return release
}

type contextCleanup struct {
	mu       sync.Mutex
	modules  map[string][]Module
	holds    int
	retired  bool
	cleaning bool
	done     chan struct{}
}

func (c *contextCleanup) acquire(ctx context.Context) (func(), bool) {
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

func (c *contextCleanup) retire() {
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

// reserveCleanup is called with mu held. Once reserved, no load can acquire
// a hold and all previously started loads have registered or failed.
func (c *contextCleanup) reserveCleanup() bool {
	if !c.retired || c.holds != 0 || c.cleaning {
		return false
	}
	c.cleaning = true
	return true
}

func (c *contextCleanup) clean() {
	// User module code runs without mu, so it can release holds or attempt
	// to load modules without deadlocking. Preserve module iteration order.
	for modName, instances := range c.modules {
		for _, inst := range instances {
			if cu, ok := inst.(CleanerUpper); ok {
				if err := cu.Cleanup(); err != nil {
					log.Printf("[ERROR] %s (%p): cleanup: %v", modName, inst, err)
				}
			}
		}
	}
	retiredCleanups.Lock()
	close(c.done)
	delete(retiredCleanups.pending, c)
	retiredCleanups.Unlock()
}

var retiredCleanups = struct {
	sync.Mutex
	pending map[*contextCleanup]struct{}
}{pending: make(map[*contextCleanup]struct{})}

// waitForCleanup waits until all explicitly retired lifecycles finish,
// including lifecycles retired by other modules' Cleanup methods. Cleanup
// is performed by cancellation or the final release, never by the waiter,
// so ctx can bound even a blocked module's Cleanup method.
func waitForCleanup(ctx context.Context) error {
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
