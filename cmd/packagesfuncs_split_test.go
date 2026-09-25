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

package caddycmd

import (
	"strings"
	"testing"
)

// TestSplitModule_StrictGoSpec is the regression test for splitModule
// silently accepting inputs that violate go.dev/ref/mod#go-mod-file-ident
// (module paths cannot contain '@'). It also checks the happy paths and
// the empty-version edge case.
func TestSplitModule_StrictGoSpec(t *testing.T) {
	for _, tt := range []struct {
		name       string
		input      string
		module     string
		version    string
		wantErr    bool
		wantErrSub string
	}{
		{
			name:    "no version",
			input:   "github.com/caddyserver/caddy",
			module:  "github.com/caddyserver/caddy",
			version: "",
		},
		{
			name:    "with version",
			input:   "github.com/caddyserver/caddy@v2.0.0",
			module:  "github.com/caddyserver/caddy",
			version: "v2.0.0",
		},
		{
			name:       "multiple '@' rejected",
			input:      "github.com/@user/module@v1.0.0",
			wantErr:    true,
			wantErrSub: "module path must not contain '@'",
		},
		{
			name:       "trailing '@' with empty version rejected",
			input:      "github.com/user/module@",
			wantErr:    true,
			wantErrSub: "version is required after '@'",
		},
		{
			name:       "empty input rejected",
			input:      "",
			wantErr:    true,
			wantErrSub: "module name is required",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			module, version, err := splitModule(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErrSub)
				}
				if !strings.Contains(err.Error(), tt.wantErrSub) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErrSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if module != tt.module {
				t.Errorf("module: got %q, want %q", module, tt.module)
			}
			if version != tt.version {
				t.Errorf("version: got %q, want %q", version, tt.version)
			}
		})
	}
}
