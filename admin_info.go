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
	"runtime"
	"runtime/debug"
)

func init() {
	RegisterModule(AdminInfo{})
}

// AdminInfo is a module that provides a GET /info endpoint on the
// admin API, returning version and build metadata about the running
// Caddy instance.
type AdminInfo struct{}

// CaddyModule returns the Caddy module information.
func (AdminInfo) CaddyModule() ModuleInfo {
	return ModuleInfo{
		ID:  "admin.api.info",
		New: func() Module { return new(AdminInfo) },
	}
}

// Routes returns a route for the /info endpoint.
func (ai AdminInfo) Routes() []AdminRoute {
	return []AdminRoute{
		{Pattern: "/info", Handler: AdminHandlerFunc(ai.handleInfo)},
	}
}

// infoResponse is the JSON structure returned by GET /info.
type infoResponse struct {
	Version       string            `json:"version"`
	VersionFull   string            `json:"version_full"`
	GoVersion     string            `json:"go_version"`
	OS            string            `json:"os"`
	Arch          string            `json:"arch"`
	BuildSettings map[string]string `json:"build_settings,omitempty"`
}

func (AdminInfo) handleInfo(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		return APIError{
			HTTPStatus: http.StatusMethodNotAllowed,
			Message:    "method not allowed",
		}
	}

	simple, full := Version()

	resp := infoResponse{
		Version:     simple,
		VersionFull: full,
		GoVersion:   runtime.Version(),
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
	}

	if bi, ok := debug.ReadBuildInfo(); ok {
		settings := make(map[string]string)
		for _, s := range bi.Settings {
			settings[s.Key] = s.Value
		}
		if len(settings) > 0 {
			resp.BuildSettings = settings
		}
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(resp)
}

// Interface guards
var _ AdminRouter = (*AdminInfo)(nil)
