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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
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
		apiErr, ok := err.(APIError)
		if !ok {
			t.Fatalf("expected APIError, got %T", err)
		}
		if apiErr.HTTPStatus != http.StatusMethodNotAllowed {
			t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, apiErr.HTTPStatus)
		}
	})
}
