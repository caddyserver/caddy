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

package logging

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestFileWriterPrepareReopen(t *testing.T) {
	dir := t.TempDir()
	current := filepath.Join(dir, "access.log")
	archive := filepath.Join(dir, "access.log.1")
	// Model the descriptors after a rename, including on systems that disallow
	// renaming an open file.
	old, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	w := &reopenableFile{file: old, config: FileWriter{Filename: current}}
	t.Cleanup(func() { _ = w.Close() })

	if err := os.Mkdir(current, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := w.PrepareReopen(); err == nil {
		t.Fatal("expected opening a directory for append to fail")
	}
	if err := os.Remove(current); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(current, []byte("existing\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	finish, err := w.PrepareReopen()
	if err != nil {
		t.Fatal(err)
	}
	if err := finish(false); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("before\n")); err != nil {
		t.Fatal(err)
	}

	finish, err = w.PrepareReopen()
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	const count = 100
	for i := range count {
		wg.Go(func() {
			if _, err := fmt.Fprintln(w, i); err != nil {
				t.Errorf("write: %v", err)
			}
		})
	}
	err = finish(true)
	wg.Wait()
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		finish, err := w.PrepareReopen()
		if err != nil || finish != nil {
			t.Fatal("same file should not need reopening", err)
		}
	}
	if _, err := w.Write([]byte("after\n")); err != nil {
		t.Fatal(err)
	}
	read := func(path string) string {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	a, b := read(archive), read(current)
	if !strings.HasPrefix(a, "before\n") || !strings.HasPrefix(b, "existing\n") || !strings.HasSuffix(b, "after\n") {
		t.Fatalf("unexpected log contents: archive %q, active %q", a, b)
	}
	counts := make(map[string]int)
	for _, line := range strings.Fields(a + b) {
		counts[line]++
	}
	for i := range count {
		if n := counts[fmt.Sprint(i)]; n != 1 {
			t.Errorf("entry %d written %d times", i, n)
		}
	}
}
