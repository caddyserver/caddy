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

package admininfo

import (
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"runtime"
	"runtime/debug"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

func TestAdminInfoModule(t *testing.T) {
	ai := AdminInfo{}
	info := ai.CaddyModule()
	if info.ID != "admin.api.info" {
		t.Errorf("expected module ID 'admin.api.info', got %q", info.ID)
	}
	routes := ai.Routes()
	if len(routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(routes))
	}
	if routes[0].Pattern != "/info" {
		t.Errorf("expected pattern '/info', got %q", routes[0].Pattern)
	}
}

func TestAdminInfoHandler(t *testing.T) {
	ai := AdminInfo{}

	t.Run("GET returns version and build info", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/info", nil)
		rec := httptest.NewRecorder()

		err := ai.handleInfo(rec, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected Content-Type 'application/json', got %q", ct)
		}

		var resp infoResponse
		if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if resp.GoVersion != runtime.Version() {
			t.Errorf("expected go_version %q, got %q", runtime.Version(), resp.GoVersion)
		}
		if resp.OS != runtime.GOOS {
			t.Errorf("expected os %q, got %q", runtime.GOOS, resp.OS)
		}
		if resp.Arch != runtime.GOARCH {
			t.Errorf("expected arch %q, got %q", runtime.GOARCH, resp.Arch)
		}
		if resp.Version == "" {
			t.Error("expected non-empty version")
		}
		if resp.VersionFull == "" {
			t.Error("expected non-empty version_full")
		}
	})

	t.Run("POST returns method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/info", nil)
		rec := httptest.NewRecorder()

		err := ai.handleInfo(rec, req)
		if err == nil {
			t.Fatal("expected error for POST method")
		}
		apiErr, ok := err.(caddy.APIError)
		if !ok {
			t.Fatalf("expected APIError, got %T", err)
		}
		if apiErr.HTTPStatus != http.StatusMethodNotAllowed {
			t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, apiErr.HTTPStatus)
		}
		if allow := rec.Header().Get("Allow"); allow != http.MethodGet {
			t.Errorf("expected Allow header %q, got %q", http.MethodGet, allow)
		}
	})
}

func TestFilterBuildSettings(t *testing.T) {
	for i, tc := range []struct {
		input    []debug.BuildSetting
		expected map[string]string
	}{
		{
			input:    nil,
			expected: nil,
		},
		{
			input: []debug.BuildSetting{
				{Key: "-ldflags", Value: "-X main.secret=hunter2"},
				{Key: "CGO_CFLAGS", Value: "-I/home/user/include"},
				{Key: "GOOS", Value: "linux"},
			},
			expected: nil,
		},
		{
			input: []debug.BuildSetting{
				{Key: "-buildmode", Value: "exe"},
				{Key: "CGO_ENABLED", Value: "1"},
				{Key: "vcs", Value: "git"},
				{Key: "vcs.revision", Value: "abc123"},
				{Key: "vcs.time", Value: "2025-07-01T12:00:00Z"},
				{Key: "vcs.modified", Value: "false"},
			},
			expected: map[string]string{
				"vcs.revision": "abc123",
				"vcs.time":     "2025-07-01T12:00:00Z",
				"vcs.modified": "false",
			},
		},
	} {
		actual := filterBuildSettings(tc.input)
		if !maps.Equal(actual, tc.expected) {
			t.Errorf("Test %d: expected %v, got %v", i, tc.expected, actual)
		}
		if tc.expected == nil && actual != nil {
			t.Errorf("Test %d: expected nil map, got %v", i, actual)
		}
	}
}
