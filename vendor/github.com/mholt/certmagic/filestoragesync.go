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
	"os"
	"path/filepath"
	"sync"
	"time"
)

// FileStorageLocker implements the Locker interface
// using the file system. An empty value is NOT VALID,
// so you must use NewFileStorageLocker() to get one.
type FileStorageLocker struct {
	fs FileStorage
}

// NewFileStorageLocker returns a valid Locker backed by fs.
func NewFileStorageLocker(fs FileStorage) *FileStorageLocker {
	return &FileStorageLocker{fs: fs}
}

// TryLock attempts to get a lock for name, otherwise it returns
// a Waiter value to wait until the other process is finished.
func (l *FileStorageLocker) TryLock(name string) (Waiter, error) {
	fileStorageNameLocksMu.Lock()
	defer fileStorageNameLocksMu.Unlock()

	// see if lock already exists within this process
	fw, ok := fileStorageNameLocks[name]
	if ok {
		// lock already created within process, let caller wait on it
		return fw, nil
	}

	// attempt to persist lock to disk by creating lock file

	// parent dir must exist
	lockDir := l.lockDir()
	if err := os.MkdirAll(lockDir, 0700); err != nil {
		return nil, err
	}

	fw = &FileStorageWaiter{
		filename: filepath.Join(lockDir, safeKey(name)+".lock"),
		wg:       new(sync.WaitGroup),
	}

	// create the file in a special mode such that an
	// error is returned if it already exists
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
	fileStorageNameLocks[name] = fw

	return nil, nil
}

// Unlock releases the lock for name.
func (l *FileStorageLocker) Unlock(name string) error {
	fileStorageNameLocksMu.Lock()
	defer fileStorageNameLocksMu.Unlock()

	fw, ok := fileStorageNameLocks[name]
	if !ok {
		return fmt.Errorf("FileStorageLocker: no lock to release for %s", name)
	}

	// remove lock file
	os.Remove(fw.filename)

	// if parent folder is now empty, remove it too to keep it tidy
	dir, err := os.Open(l.lockDir()) // OK to ignore error here
	if err == nil {
		items, _ := dir.Readdirnames(3) // OK to ignore error here
		if len(items) == 0 {
			os.Remove(dir.Name())
		}
		dir.Close()
	}

	// clean up in memory
	fw.wg.Done()
	delete(fileStorageNameLocks, name)

	return nil
}

func (l *FileStorageLocker) lockDir() string {
	return filepath.Join(l.fs.Path, "locks")
}

// FileStorageWaiter waits for a file to disappear; it
// polls the file system to check for the existence of
// a file. It also uses a WaitGroup to optimize the
// polling in the case when this process is the only
// one waiting. (Other processes that are waiting
// for the lock will still block, but must wait
// for the poll intervals to get their answer.)
type FileStorageWaiter struct {
	filename string
	wg       *sync.WaitGroup
}

// Wait waits until the lock is released.
func (fw *FileStorageWaiter) Wait() {
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

var fileStorageNameLocks = make(map[string]*FileStorageWaiter)
var fileStorageNameLocksMu sync.Mutex

var _ Locker = &FileStorageLocker{}
var _ Waiter = &FileStorageWaiter{}
