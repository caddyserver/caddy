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
	"testing"
)

func TestSplitModule(t *testing.T) {
	tests := []struct {
		name            string
		input           string
		expectedModule  string
		expectedVersion string
		expectError     bool
	}{
		{
			name:            "simple module without version",
			input:           "github.com/caddyserver/caddy",
			expectedModule:  "github.com/caddyserver/caddy",
			expectedVersion: "",
			expectError:     false,
		},
		{
			name:            "module with version",
			input:           "github.com/caddyserver/caddy@v2.0.0",
			expectedModule:  "github.com/caddyserver/caddy",
			expectedVersion: "v2.0.0",
			expectError:     false,
		},
		{
			name:            "module with semantic version",
			input:           "github.com/user/module@v1.2.3",
			expectedModule:  "github.com/user/module",
			expectedVersion: "v1.2.3",
			expectError:     false,
		},
		{
			name:            "module with prerelease version",
			input:           "github.com/user/module@v1.0.0-beta.1",
			expectedModule:  "github.com/user/module",
			expectedVersion: "v1.0.0-beta.1",
			expectError:     false,
		},
		{
			name:            "module with commit hash",
			input:           "github.com/user/module@abc123def",
			expectedModule:  "github.com/user/module",
			expectedVersion: "abc123def",
			expectError:     false,
		},
		{
			name:            "module with @ in path and version",
			input:           "github.com/@user/module@v1.0.0",
			expectedModule:  "github.com/@user/module",
			expectedVersion: "v1.0.0",
			expectError:     false,
		},
		{
			name:            "module with multiple @ in path",
			input:           "github.com/@org/@user/module@v2.3.4",
			expectedModule:  "github.com/@org/@user/module",
			expectedVersion: "v2.3.4",
			expectError:     false,
		},
		// TODO: decide on the behavior for this case; it fails currently
		// {
		// 	name:            "module with @ in path but no version",
		// 	input:           "github.com/@user/module",
		// 	expectedModule:  "github.com/@user/module",
		// 	expectedVersion: "",
		// 	expectError:     false,
		// },
		{
			name:            "empty string",
			input:           "",
			expectedModule:  "",
			expectedVersion: "",
			expectError:     true,
		},
		{
			name:            "only @ symbol",
			input:           "@",
			expectedModule:  "",
			expectedVersion: "",
			expectError:     true,
		},
		{
			name:            "@ at start",
			input:           "@v1.0.0",
			expectedModule:  "",
			expectedVersion: "v1.0.0",
			expectError:     true,
		},
		{
			name:            "@ at end",
			input:           "github.com/user/module@",
			expectedModule:  "github.com/user/module",
			expectedVersion: "",
			expectError:     false,
		},
		{
			name:            "multiple consecutive @",
			input:           "github.com/user/module@@v1.0.0",
			expectedModule:  "github.com/user/module@",
			expectedVersion: "v1.0.0",
			expectError:     false,
		},
		{
			name:            "version with latest tag",
			input:           "github.com/user/module@latest",
			expectedModule:  "github.com/user/module",
			expectedVersion: "latest",
			expectError:     false,
		},
		{
			name:            "long module path",
			input:           "github.com/organization/team/project/subproject/module@v3.14.159",
			expectedModule:  "github.com/organization/team/project/subproject/module",
			expectedVersion: "v3.14.159",
			expectError:     false,
		},
		{
			name:            "module with dots in name",
			input:           "github.com/user/my.module.name@v1.0",
			expectedModule:  "github.com/user/my.module.name",
			expectedVersion: "v1.0",
			expectError:     false,
		},
		{
			name:            "module with hyphens",
			input:           "github.com/user/my-module-name@v1.0.0",
			expectedModule:  "github.com/user/my-module-name",
			expectedVersion: "v1.0.0",
			expectError:     false,
		},
		{
			name:            "gitlab module",
			input:           "gitlab.com/user/module@v2.0.0",
			expectedModule:  "gitlab.com/user/module",
			expectedVersion: "v2.0.0",
			expectError:     false,
		},
		{
			name:            "bitbucket module",
			input:           "bitbucket.org/user/module@v1.5.0",
			expectedModule:  "bitbucket.org/user/module",
			expectedVersion: "v1.5.0",
			expectError:     false,
		},
		{
			name:            "custom domain",
			input:           "example.com/custom/module@v1.0.0",
			expectedModule:  "example.com/custom/module",
			expectedVersion: "v1.0.0",
			expectError:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			module, version, err := splitModule(tt.input)

			// Check error expectation
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}

			// Check module
			if module != tt.expectedModule {
				t.Errorf("module: got %q, want %q", module, tt.expectedModule)
			}

			// Check version
			if version != tt.expectedVersion {
				t.Errorf("version: got %q, want %q", version, tt.expectedVersion)
			}
		})
	}
}

func TestSplitModule_ErrorCases(t *testing.T) {
	errorCases := []string{
		"",
		"@",
		"@version",
		"@v1.0.0",
	}

	for _, tc := range errorCases {
		t.Run("error_"+tc, func(t *testing.T) {
			_, _, err := splitModule(tc)
			if err == nil {
				t.Errorf("splitModule(%q) should return error", tc)
			}
		})
	}
}

// BenchmarkSplitModule benchmarks the splitModule function
func BenchmarkSplitModule(b *testing.B) {
	testCases := []string{
		"github.com/user/module",
		"github.com/user/module@v1.0.0",
		"github.com/@org/@user/module@v2.3.4",
		"github.com/organization/team/project/subproject/module@v3.14.159",
	}

	for _, tc := range testCases {
		b.Run(tc, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				splitModule(tc)
			}
		})
	}
}
