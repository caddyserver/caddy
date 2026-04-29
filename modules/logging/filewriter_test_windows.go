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

//go:build windows

package logging

import (
	"os"
	"path"
	"testing"
)

// Windows relies on ACLs instead of unix permissions model.
// Go allows to open files with a particular mode but it is limited to read or write.
// See https://cs.opensource.google/go/go/+/refs/tags/go1.22.3:src/syscall/syscall_windows.go;l=708.
// This is pretty restrictive and has little interest for log files and thus we just test that log files are
// opened with R/W permissions by default on Windows too.
func TestFileCreationMode(t *testing.T) {
	dir, err := os.MkdirTemp("", "caddytest")
	if err != nil {
		t.Fatalf("failed to create tempdir: %v", err)
	}
	defer os.RemoveAll(dir)

	fw := &FileWriter{
		Filename: path.Join(dir, "test.log"),
	}

	logger, err := fw.OpenWriter()
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	defer logger.Close()

	st, err := os.Stat(fw.Filename)
	if err != nil {
		t.Fatalf("failed to check file permissions: %v", err)
	}

	if st.Mode().Perm()&0o600 != 0o600 {
		t.Fatalf("file mode is %v, want rw for user", st.Mode().Perm())
	}
}

func TestDirMode_Windows_CreateSucceeds(t *testing.T) {
	dir, err := os.MkdirTemp("", "caddytest")
	if err != nil {
		t.Fatalf("failed to create tempdir: %v", err)
	}
	defer os.RemoveAll(dir)

	tests := []struct {
		name    string
		dirMode string
	}{
		{"inherit", "inherit"},
		{"from_file", "from_file"},
		{"octal", "0755"},
		{"default", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subdir := path.Join(dir, "logs-"+tt.name)
			fw := &FileWriter{
				Filename: path.Join(subdir, "test.log"),
				DirMode:  tt.dirMode,
				Mode:     0o600,
			}
			w, err := fw.OpenWriter()
			if err != nil {
				t.Fatalf("failed to open writer: %v", err)
			}
			defer w.Close()

			if _, err := os.Stat(fw.Filename); err != nil {
				t.Fatalf("expected file to exist: %v", err)
			}
		})
	}
}
