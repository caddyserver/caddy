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
	"fmt"
	"io/fs"
	"sync"
	"testing"
	"time"
)

// Mock filesystem implementation for testing
type mockFileSystem struct {
	name  string
	files map[string]string
}

func (m *mockFileSystem) Open(name string) (fs.File, error) {
	if content, exists := m.files[name]; exists {
		return &mockFile{name: name, content: content}, nil
	}
	return nil, fs.ErrNotExist
}

type mockFile struct {
	name    string
	content string
	pos     int
}

func (m *mockFile) Stat() (fs.FileInfo, error) {
	return &mockFileInfo{name: m.name, size: int64(len(m.content))}, nil
}

func (m *mockFile) Read(b []byte) (int, error) {
	if m.pos >= len(m.content) {
		return 0, fs.ErrClosed
	}
	n := copy(b, m.content[m.pos:])
	m.pos += n
	return n, nil
}

func (m *mockFile) Close() error {
	return nil
}

type mockFileInfo struct {
	name string
	size int64
}

func (m *mockFileInfo) Name() string      { return m.name }
func (m *mockFileInfo) Size() int64       { return m.size }
func (m *mockFileInfo) Mode() fs.FileMode { return 0o644 }
func (m *mockFileInfo) ModTime() time.Time {
	return time.Time{}
}
func (m *mockFileInfo) IsDir() bool { return false }
func (m *mockFileInfo) Sys() any    { return nil }

// Mock FileSystems implementation for testing
type mockFileSystems struct {
	mu          sync.RWMutex
	filesystems map[string]fs.FS
	defaultFS   fs.FS
}

func newMockFileSystems() *mockFileSystems {
	return &mockFileSystems{
		filesystems: make(map[string]fs.FS),
		defaultFS:   &mockFileSystem{name: "default", files: map[string]string{"default.txt": "default content"}},
	}
}

func (m *mockFileSystems) Register(k string, v fs.FS) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.filesystems[k] = v
}

func (m *mockFileSystems) Unregister(k string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.filesystems, k)
}

func (m *mockFileSystems) Get(k string) (fs.FS, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.filesystems[k]
	return v, ok
}

func (m *mockFileSystems) Default() fs.FS {
	return m.defaultFS
}

func TestFileSystems_Register_Get(t *testing.T) {
	fsys := newMockFileSystems()
	mockFS := &mockFileSystem{
		name:  "test",
		files: map[string]string{"test.txt": "test content"},
	}

	// Register filesystem
	fsys.Register("test", mockFS)

	// Retrieve filesystem
	retrieved, exists := fsys.Get("test")
	if !exists {
		t.Error("Expected filesystem to exist after registration")
	}
	if retrieved != mockFS {
		t.Error("Retrieved filesystem is not the same as registered")
	}
}

func TestFileSystems_Unregister(t *testing.T) {
	fsys := newMockFileSystems()
	mockFS := &mockFileSystem{name: "test"}

	// Register then unregister
	fsys.Register("test", mockFS)
	fsys.Unregister("test")

	// Should not exist after unregistration
	_, exists := fsys.Get("test")
	if exists {
		t.Error("Filesystem should not exist after unregistration")
	}
}

func TestFileSystems_Default(t *testing.T) {
	fsys := newMockFileSystems()

	defaultFS := fsys.Default()
	if defaultFS == nil {
		t.Error("Default filesystem should not be nil")
	}

	// Test that default filesystem works
	file, err := defaultFS.Open("default.txt")
	if err != nil {
		t.Fatalf("Failed to open default file: %v", err)
	}
	defer file.Close()

	data := make([]byte, 100)
	n, err := file.Read(data)
	if err != nil && err != fs.ErrClosed {
		t.Fatalf("Failed to read default file: %v", err)
	}

	content := string(data[:n])
	if content != "default content" {
		t.Errorf("Expected 'default content', got '%s'", content)
	}
}

func TestFileSystems_Concurrent_Access(t *testing.T) {
	fsys := newMockFileSystems()

	const numGoroutines = 50
	const numOperations = 10

	var wg sync.WaitGroup

	// Concurrent register/unregister/get operations
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			key := fmt.Sprintf("fs-%d", id)
			mockFS := &mockFileSystem{
				name:  key,
				files: map[string]string{key + ".txt": "content"},
			}

			for j := 0; j < numOperations; j++ {
				// Register
				fsys.Register(key, mockFS)

				// Get
				retrieved, exists := fsys.Get(key)
				if !exists {
					t.Errorf("Filesystem %s should exist", key)
					continue
				}
				if retrieved != mockFS {
					t.Errorf("Retrieved filesystem for %s is not correct", key)
				}

				// Test file access
				file, err := retrieved.Open(key + ".txt")
				if err != nil {
					t.Errorf("Failed to open file in %s: %v", key, err)
					continue
				}
				file.Close()

				// Unregister
				fsys.Unregister(key)

				// Should not exist after unregister
				_, stillExists := fsys.Get(key)
				if stillExists {
					t.Errorf("Filesystem %s should not exist after unregister", key)
				}
			}
		}(i)
	}

	wg.Wait()
}

func TestFileSystems_Get_NonExistent(t *testing.T) {
	fsys := newMockFileSystems()

	_, exists := fsys.Get("non-existent")
	if exists {
		t.Error("Non-existent filesystem should not exist")
	}
}

func TestFileSystems_Register_Overwrite(t *testing.T) {
	fsys := newMockFileSystems()
	key := "overwrite-test"

	// Register first filesystem
	fs1 := &mockFileSystem{name: "fs1"}
	fsys.Register(key, fs1)

	// Register second filesystem with same key (should overwrite)
	fs2 := &mockFileSystem{name: "fs2"}
	fsys.Register(key, fs2)

	// Should get the second filesystem
	retrieved, exists := fsys.Get(key)
	if !exists {
		t.Error("Filesystem should exist")
	}
	if retrieved != fs2 {
		t.Error("Should get the overwritten filesystem")
	}
	if retrieved == fs1 {
		t.Error("Should not get the original filesystem")
	}
}

func TestFileSystems_Concurrent_RegisterUnregister_SameKey(t *testing.T) {
	fsys := newMockFileSystems()
	key := "concurrent-key"

	const numGoroutines = 20
	var wg sync.WaitGroup

	// Half the goroutines register, half unregister
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		if i%2 == 0 {
			go func(id int) {
				defer wg.Done()
				mockFS := &mockFileSystem{name: fmt.Sprintf("fs-%d", id)}
				fsys.Register(key, mockFS)
			}(i)
		} else {
			go func() {
				defer wg.Done()
				fsys.Unregister(key)
			}()
		}
	}

	wg.Wait()

	// The final state is unpredictable due to race conditions,
	// but the operations should not panic or cause corruption
	// Test passes if we reach here without issues
}

func TestFileSystems_StressTest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	fsys := newMockFileSystems()

	const numGoroutines = 100
	const duration = 100 * time.Millisecond

	var wg sync.WaitGroup
	stopChan := make(chan struct{})

	// Start timer
	go func() {
		time.Sleep(duration)
		close(stopChan)
	}()

	// Stress test with continuous operations
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			key := fmt.Sprintf("stress-fs-%d", id%10) // Use limited set of keys
			mockFS := &mockFileSystem{
				name:  key,
				files: map[string]string{key + ".txt": "stress content"},
			}

			for {
				select {
				case <-stopChan:
					return
				default:
					// Rapid register/get/unregister cycles
					fsys.Register(key, mockFS)

					if retrieved, exists := fsys.Get(key); exists {
						// Try to use the filesystem
						if file, err := retrieved.Open(key + ".txt"); err == nil {
							file.Close()
						}
					}

					fsys.Unregister(key)
				}
			}
		}(i)
	}

	wg.Wait()

	// Test passes if we reach here without panics or deadlocks
}
