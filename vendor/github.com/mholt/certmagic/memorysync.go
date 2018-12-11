// Copyright 2015 Matthew Holt
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

package certmagic

import (
	"fmt"
	"sync"
)

// MemoryLocker implements the Locker interface
// using memory. An empty value is NOT VALID,
// so you must use NewMemoryLocker() to get one.
type MemoryLocker struct {
	nameLocks   map[string]*MemoryWaiter
	nameLocksMu *sync.Mutex
}

// NewMemoryLocker returns a valid Locker backed by fs.
func NewMemoryLocker() *MemoryLocker {
	return &MemoryLocker{
		nameLocks:   make(map[string]*MemoryWaiter),
		nameLocksMu: new(sync.Mutex),
	}
}

// TryLock attempts to get a lock for name, otherwise it returns
// a Waiter value to wait until the other process is finished.
func (l *MemoryLocker) TryLock(name string) (Waiter, error) {
	l.nameLocksMu.Lock()
	defer l.nameLocksMu.Unlock()

	// see if lock already exists within this process
	w, ok := l.nameLocks[name]
	if ok {
		return w, nil
	}

	// we got the lock, so create it
	w = &MemoryWaiter{wg: new(sync.WaitGroup)}
	w.wg.Add(1)
	l.nameLocks[name] = w

	return nil, nil
}

// Unlock releases the lock for name.
func (l *MemoryLocker) Unlock(name string) error {
	l.nameLocksMu.Lock()
	defer l.nameLocksMu.Unlock()

	w, ok := l.nameLocks[name]
	if !ok {
		return fmt.Errorf("MemoryLocker: no lock to release for %s", name)
	}

	w.wg.Done()
	delete(l.nameLocks, name)

	return nil
}

// MemoryWaiter implements Waiter in memory.
type MemoryWaiter struct {
	wg *sync.WaitGroup
}

// Wait waits until w.wg is done.
func (w *MemoryWaiter) Wait() {
	w.Wait()
}

var _ Locker = &MemoryLocker{}
var _ Waiter = &MemoryWaiter{}
