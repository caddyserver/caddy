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
	"net/http"
	"runtime"
	"runtime/debug"
	"slices"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(AdminInfo{})
}

// AdminInfo is a module that provides a GET /info endpoint on the
// admin API, returning version and build metadata about the running
// Caddy instance.
type AdminInfo struct{}

// CaddyModule returns the Caddy module information.
func (AdminInfo) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "admin.api.info",
		New: func() caddy.Module { return new(AdminInfo) },
	}
}

// Routes returns a route for the /info endpoint.
func (ai AdminInfo) Routes() []caddy.AdminRoute {
	return []caddy.AdminRoute{
		{Pattern: "/info", Handler: caddy.AdminHandlerFunc(ai.handleInfo)},
	}
}

// infoResponse is the JSON structure returned by GET /info. Its
// fields are part of the admin API contract.
type infoResponse struct {
	// Version is the short version string, as printed by `caddy version`.
	Version string `json:"version"`

	// VersionFull is the full version string, which may include
	// the module checksum.
	VersionFull string `json:"version_full"`

	// GoVersion is the Go toolchain version used to build Caddy.
	GoVersion string `json:"go_version"`

	// OS is the target operating system.
	OS string `json:"os"`

	// Arch is the target architecture.
	Arch string `json:"arch"`

	// BuildSettings contains the VCS metadata embedded at build time,
	// limited to the keys in exposedBuildSettings. It is omitted when
	// unavailable, such as for builds made with `go install` or xcaddy.
	BuildSettings map[string]string `json:"build_settings,omitempty"`
}

// exposedBuildSettings lists the build setting keys included in the
// response. Other settings, such as compiler and linker flags, vary
// by toolchain and may contain local paths or injected values, so
// they are not exposed.
var exposedBuildSettings = []string{
	"vcs.revision",
	"vcs.time",
	"vcs.modified",
}

func (AdminInfo) handleInfo(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		return caddy.APIError{
			HTTPStatus: http.StatusMethodNotAllowed,
			Message:    "method not allowed",
		}
	}

	simple, full := caddy.Version()

	resp := infoResponse{
		Version:     simple,
		VersionFull: full,
		GoVersion:   runtime.Version(),
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
	}

	if bi, ok := debug.ReadBuildInfo(); ok {
		resp.BuildSettings = filterBuildSettings(bi.Settings)
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(resp)
}

// filterBuildSettings returns the settings whose keys are in
// exposedBuildSettings, or nil if there are none.
func filterBuildSettings(settings []debug.BuildSetting) map[string]string {
	var filtered map[string]string
	for _, s := range settings {
		if !slices.Contains(exposedBuildSettings, s.Key) {
			continue
		}
		if filtered == nil {
			filtered = make(map[string]string)
		}
		filtered[s.Key] = s.Value
	}
	return filtered
}

// Interface guards
var _ caddy.AdminRouter = (*AdminInfo)(nil)
