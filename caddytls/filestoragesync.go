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
	"os"
	"sync"
	"time"

	"github.com/mholt/caddy"
)

func init() {
	// be sure to remove lock files when exiting the process!
	caddy.OnProcessExit = append(caddy.OnProcessExit, func() {
		fileStorageNameLocksMu.Lock()
		defer fileStorageNameLocksMu.Unlock()
		for key, fw := range fileStorageNameLocks {
			os.Remove(fw.filename)
			delete(fileStorageNameLocks, key)
		}
	})
}

// fileStorageLock facilitates ACME-related locking by using
// the associated FileStorage, so multiple processes can coordinate
// renewals on the certificates on a shared file system.
type fileStorageLock struct {
	caURL   string
	storage *FileStorage
}

// TryLock attempts to get a lock for name, otherwise it returns
// a Waiter value to wait until the other process is finished.
func (s *fileStorageLock) TryLock(name string) (Waiter, error) {
	fileStorageNameLocksMu.Lock()
	defer fileStorageNameLocksMu.Unlock()

	// see if lock already exists within this process
	fw, ok := fileStorageNameLocks[s.caURL+name]
	if ok {
		// lock already created within process, let caller wait on it
		return fw, nil
	}

	// attempt to persist lock to disk by creating lock file
	fw = &fileWaiter{
		filename: s.storage.siteCertFile(name) + ".lock",
		wg:       new(sync.WaitGroup),
	}
	// parent dir must exist
	if err := os.MkdirAll(s.storage.site(name), 0700); err != nil {
		return nil, err
	}
	lf, err := os.OpenFile(fw.filename, os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		if os.IsExist(err) {
			// another process has the lock; use it to wait
			return fw, nil
		}
		// otherwise, this was some unexpected error
		return nil, err
	}
	lf.Close()

	// looks like we get the lock
	fw.wg.Add(1)
	fileStorageNameLocks[s.caURL+name] = fw

	return nil, nil
}

// Unlock unlocks name.
func (s *fileStorageLock) Unlock(name string) error {
	fileStorageNameLocksMu.Lock()
	defer fileStorageNameLocksMu.Unlock()
	fw, ok := fileStorageNameLocks[s.caURL+name]
	if !ok {
		return fmt.Errorf("FileStorage: no lock to release for %s", name)
	}
	os.Remove(fw.filename)
	fw.wg.Done()
	delete(fileStorageNameLocks, s.caURL+name)
	return nil
}

// fileWaiter waits for a file to disappear; it polls
// the file system to check for the existence of a file.
// It also has a WaitGroup which will be faster than
// polling, for when locking need only happen within this
// process.
type fileWaiter struct {
	filename string
	wg       *sync.WaitGroup
}

// Wait waits until the lock is released.
func (fw *fileWaiter) Wait() {
	start := time.Now()
	fw.wg.Wait()
	for time.Since(start) < 1*time.Hour {
		_, err := os.Stat(fw.filename)
		if os.IsNotExist(err) {
			return
		}
		time.Sleep(1 * time.Second)
	}
}

var fileStorageNameLocks = make(map[string]*fileWaiter) // keyed by CA + name
var fileStorageNameLocksMu sync.Mutex

var _ Locker = &fileStorageLock{}
var _ Waiter = &fileWaiter{}
