// Copyright 2015 Light Code Labs, LLC
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

package caddytls

import (
	"fmt"
	"sync"
)

var _ Locker = &syncLock{}

type syncLock struct {
	nameLocks   map[string]*sync.WaitGroup
	nameLocksMu sync.Mutex
}

// TryLock attempts to get a lock for name, otherwise it returns
// a Waiter value to wait until the other process is finished.
func (s *syncLock) TryLock(name string) (Waiter, error) {
	s.nameLocksMu.Lock()
	defer s.nameLocksMu.Unlock()
	wg, ok := s.nameLocks[name]
	if ok {
		// lock already obtained, let caller wait on it
		return wg, nil
	}
	// caller gets lock
	wg = new(sync.WaitGroup)
	wg.Add(1)
	s.nameLocks[name] = wg
	return nil, nil
}

// Unlock unlocks name.
func (s *syncLock) Unlock(name string) error {
	s.nameLocksMu.Lock()
	defer s.nameLocksMu.Unlock()
	wg, ok := s.nameLocks[name]
	if !ok {
		return fmt.Errorf("FileStorage: no lock to release for %s", name)
	}
	wg.Done()
	delete(s.nameLocks, name)
	return nil
}
