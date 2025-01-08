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

//go:build !windows

package logging

import (
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestFileCreationMode(t *testing.T) {
	on := true
	off := false

	tests := []struct {
		name     string
		fw       FileWriter
		wantMode os.FileMode
	}{
		{
			name: "default mode no roll",
			fw: FileWriter{
				Roll: &off,
			},
			wantMode: 0o600,
		},
		{
			name: "default mode roll",
			fw: FileWriter{
				Roll: &on,
			},
			wantMode: 0o600,
		},
		{
			name: "custom mode no roll",
			fw: FileWriter{
				Roll: &off,
				Mode: 0o666,
			},
			wantMode: 0o666,
		},
		{
			name: "custom mode roll",
			fw: FileWriter{
				Roll: &on,
				Mode: 0o666,
			},
			wantMode: 0o666,
		},
	}

	m := syscall.Umask(0o000)
	defer syscall.Umask(m)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, err := os.MkdirTemp("", "caddytest")
			if err != nil {
				t.Fatalf("failed to create tempdir: %v", err)
			}
			defer os.RemoveAll(dir)
			fpath := filepath.Join(dir, "test.log")
			tt.fw.Filename = fpath

			logger, err := tt.fw.OpenWriter()
			if err != nil {
				t.Fatalf("failed to create file: %v", err)
			}
			defer logger.Close()

			st, err := os.Stat(fpath)
			if err != nil {
				t.Fatalf("failed to check file permissions: %v", err)
			}

			if st.Mode() != tt.wantMode {
				t.Errorf("%s: file mode is %v, want %v", tt.name, st.Mode(), tt.wantMode)
			}
		})
	}
}

func TestFileRotationPreserveMode(t *testing.T) {
	m := syscall.Umask(0o000)
	defer syscall.Umask(m)

	dir, err := os.MkdirTemp("", "caddytest")
	if err != nil {
		t.Fatalf("failed to create tempdir: %v", err)
	}
	defer os.RemoveAll(dir)

	fpath := path.Join(dir, "test.log")

	roll := true
	mode := fileMode(0o640)
	fw := FileWriter{
		Filename:   fpath,
		Mode:       mode,
		Roll:       &roll,
		RollSizeMB: 1,
	}

	logger, err := fw.OpenWriter()
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	defer logger.Close()

	b := make([]byte, 1024*1024-1000)
	logger.Write(b)
	logger.Write(b[0:2000])

	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("failed to read temporary log dir: %v", err)
	}

	// We might get 2 or 3 files depending
	// on the race between compressed log file generation,
	// removal of the non compressed file and reading the directory.
	// Ordering of the files are [ test-*.log test-*.log.gz test.log ]
	if len(files) < 2 || len(files) > 3 {
		t.Log("got files: ", files)
		t.Fatalf("got %v files want 2", len(files))
	}

	wantPattern := "test-*-*-*-*-*.*.log"
	test_date_log := files[0]
	if m, _ := path.Match(wantPattern, test_date_log.Name()); m != true {
		t.Fatalf("got %v filename want %v", test_date_log.Name(), wantPattern)
	}

	st, err := os.Stat(path.Join(dir, test_date_log.Name()))
	if err != nil {
		t.Fatalf("failed to check file permissions: %v", err)
	}

	if st.Mode() != os.FileMode(mode) {
		t.Errorf("file mode is %v, want %v", st.Mode(), mode)
	}

	test_dot_log := files[len(files)-1]
	if test_dot_log.Name() != "test.log" {
		t.Fatalf("got %v filename want test.log", test_dot_log.Name())
	}

	st, err = os.Stat(path.Join(dir, test_dot_log.Name()))
	if err != nil {
		t.Fatalf("failed to check file permissions: %v", err)
	}

	if st.Mode() != os.FileMode(mode) {
		t.Errorf("file mode is %v, want %v", st.Mode(), mode)
	}
}

func TestFileModeConfig(t *testing.T) {
	tests := []struct {
		name    string
		d       *caddyfile.Dispenser
		fw      FileWriter
		wantErr bool
	}{
		{
			name: "set mode",
			d: caddyfile.NewTestDispenser(`
file test.log {
	mode 0666
}
`),
			fw: FileWriter{
				Mode: 0o666,
			},
			wantErr: false,
		},
		{
			name: "set mode 3 digits",
			d: caddyfile.NewTestDispenser(`
file test.log {
	mode 666
}
`),
			fw: FileWriter{
				Mode: 0o666,
			},
			wantErr: false,
		},
		{
			name: "set mode 2 digits",
			d: caddyfile.NewTestDispenser(`
file test.log {
	mode 66
}
`),
			fw: FileWriter{
				Mode: 0o066,
			},
			wantErr: false,
		},
		{
			name: "set mode 1 digits",
			d: caddyfile.NewTestDispenser(`
file test.log {
	mode 6
}
`),
			fw: FileWriter{
				Mode: 0o006,
			},
			wantErr: false,
		},
		{
			name: "invalid mode",
			d: caddyfile.NewTestDispenser(`
file test.log {
	mode foobar
}
`),
			fw:      FileWriter{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fw := &FileWriter{}
			if err := fw.UnmarshalCaddyfile(tt.d); (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalCaddyfile() error = %v, want %v", err, tt.wantErr)
			}
			if fw.Mode != tt.fw.Mode {
				t.Errorf("got mode %v, want %v", fw.Mode, tt.fw.Mode)
			}
		})
	}
}

func TestFileModeJSON(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		fw      FileWriter
		wantErr bool
	}{
		{
			name: "set mode",
			config: `
{
	"mode": "0666"
}
`,
			fw: FileWriter{
				Mode: 0o666,
			},
			wantErr: false,
		},
		{
			name: "set mode invalid value",
			config: `
{
	"mode": "0x666"
}
`,
			fw:      FileWriter{},
			wantErr: true,
		},
		{
			name: "set mode invalid string",
			config: `
{
	"mode": 777
}
`,
			fw:      FileWriter{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fw := &FileWriter{}
			if err := json.Unmarshal([]byte(tt.config), fw); (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalJSON() error = %v, want %v", err, tt.wantErr)
			}
			if fw.Mode != tt.fw.Mode {
				t.Errorf("got mode %v, want %v", fw.Mode, tt.fw.Mode)
			}
		})
	}
}

func TestFileModeToJSON(t *testing.T) {
	tests := []struct {
		name    string
		mode    fileMode
		want    string
		wantErr bool
	}{
		{
			name:    "none zero",
			mode:    0644,
			want:    `"0644"`,
			wantErr: false,
		},
		{
			name:    "zero mode",
			mode:    0,
			want:    `"0000"`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b []byte
			var err error

			if b, err = json.Marshal(&tt.mode); (err != nil) != tt.wantErr {
				t.Fatalf("MarshalJSON() error = %v, want %v", err, tt.wantErr)
			}

			got := string(b[:])

			if got != tt.want {
				t.Errorf("got mode %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFileModeModification(t *testing.T) {
	m := syscall.Umask(0o000)
	defer syscall.Umask(m)

	dir, err := os.MkdirTemp("", "caddytest")
	if err != nil {
		t.Fatalf("failed to create tempdir: %v", err)
	}
	defer os.RemoveAll(dir)

	fpath := path.Join(dir, "test.log")
	f_tmp, err := os.OpenFile(fpath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, os.FileMode(0600))
	if err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}
	f_tmp.Close()

	fw := FileWriter{
		Mode:     0o666,
		Filename: fpath,
	}

	logger, err := fw.OpenWriter()
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	defer logger.Close()

	st, err := os.Stat(fpath)
	if err != nil {
		t.Fatalf("failed to check file permissions: %v", err)
	}

	want := os.FileMode(fw.Mode)
	if st.Mode() != want {
		t.Errorf("file mode is %v, want %v", st.Mode(), want)
	}
}
