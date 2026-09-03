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

package fileserver

import (
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestUnmarshalCaddyfileBrowseFileLimit(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantLimit int
		wantErr   string
	}{
		{
			name: "valid positive integer",
			input: `file_server {
	browse {
		file_limit 4000
	}
}`,
			wantLimit: 4000,
		},
		{
			name: "valid with sort options",
			input: `file_server {
	browse {
		sort time desc
		file_limit 250
	}
}`,
			wantLimit: 250,
		},
		{
			name: "non-integer value",
			input: `file_server {
	browse {
		file_limit notanint
	}
}`,
			wantErr: "file_limit must be an integer",
		},
		{
			name: "partially numeric value",
			input: `file_server {
	browse {
		file_limit 12abc
	}
}`,
			wantErr: "file_limit must be an integer",
		},
		{
			name: "zero is rejected",
			input: `file_server {
	browse {
		file_limit 0
	}
}`,
			wantErr: "file_limit must be a positive integer",
		},
		{
			name: "negative is rejected",
			input: `file_server {
	browse {
		file_limit -5
	}
}`,
			wantErr: "file_limit must be a positive integer",
		},
		{
			name: "missing argument",
			input: `file_server {
	browse {
		file_limit
	}
}`,
			wantErr: "file_limit requires exactly one positive integer argument",
		},
		{
			name: "too many arguments",
			input: `file_server {
	browse {
		file_limit 10 20
	}
}`,
			wantErr: "file_limit requires exactly one positive integer argument",
		},
		{
			name: "duplicate file_limit",
			input: `file_server {
	browse {
		file_limit 10
		file_limit 20
	}
}`,
			wantErr: "file_limit is already configured",
		},
		{
			name: "empty string argument",
			input: `file_server {
	browse {
		file_limit ""
	}
}`,
			wantErr: "file_limit must be an integer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tt.input)
			fsrv := new(FileServer)
			err := fsrv.UnmarshalCaddyfile(d)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil (FileLimit=%d)", tt.wantErr, fsrv.Browse.FileLimit)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if fsrv.Browse == nil {
				t.Fatal("expected Browse to be configured")
			}
			if fsrv.Browse.FileLimit != tt.wantLimit {
				t.Fatalf("FileLimit = %d, want %d", fsrv.Browse.FileLimit, tt.wantLimit)
			}
		})
	}
}

func TestUnmarshalCaddyfileBrowseBlock(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		wantSymlinks  bool
		wantSort      []string
		wantFileLimit int
		wantErr       string
	}{
		{
			name: "reveal_symlinks and sort",
			input: `file_server {
	browse {
		reveal_symlinks
		sort namedirfirst asc
	}
}`,
			wantSymlinks: true,
			wantSort:     []string{"namedirfirst", "asc"},
		},
		{
			name: "unknown browse subdirective",
			input: `file_server {
	browse {
		not_a_thing
	}
}`,
			wantErr: "unknown subdirective",
		},
		{
			name: "unknown sort option",
			input: `file_server {
	browse {
		sort by_magic
	}
}`,
			wantErr: "unknown sort option",
		},
		{
			name: "full browse block",
			input: `file_server {
	browse {
		reveal_symlinks
		sort size desc
		file_limit 100
	}
}`,
			wantSymlinks:  true,
			wantSort:      []string{"size", "desc"},
			wantFileLimit: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tt.input)
			fsrv := new(FileServer)
			err := fsrv.UnmarshalCaddyfile(d)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if fsrv.Browse == nil {
				t.Fatal("expected Browse to be configured")
			}
			if fsrv.Browse.RevealSymlinks != tt.wantSymlinks {
				t.Fatalf("RevealSymlinks = %v, want %v", fsrv.Browse.RevealSymlinks, tt.wantSymlinks)
			}
			if len(tt.wantSort) > 0 {
				if len(fsrv.Browse.SortOptions) != len(tt.wantSort) {
					t.Fatalf("SortOptions = %#v, want %#v", fsrv.Browse.SortOptions, tt.wantSort)
				}
				for i := range tt.wantSort {
					if fsrv.Browse.SortOptions[i] != tt.wantSort[i] {
						t.Fatalf("SortOptions[%d] = %q, want %q", i, fsrv.Browse.SortOptions[i], tt.wantSort[i])
					}
				}
			}
			if fsrv.Browse.FileLimit != tt.wantFileLimit {
				t.Fatalf("FileLimit = %d, want %d", fsrv.Browse.FileLimit, tt.wantFileLimit)
			}
		})
	}
}
