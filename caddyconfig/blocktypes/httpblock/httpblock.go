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

package httpblock

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/blocktypes"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
)

func init() {
	blocktypes.RegisterBlockType("http", Setup)
}

// Setup processes HTTP server blocks and mutates the provided Caddy config.
// This extracts the HTTP processing logic from httpcaddyfile.ServerType.Setup()
// so it can be reused by both the standard httpcaddyfile adapter and the xcaddyfile adapter.
func Setup(cfg *caddy.Config, blocks []caddyfile.ServerBlock, options map[string]any) ([]caddyconfig.Warning, error) {
	// Delegate to the existing httpcaddyfile.ServerType for now
	// We'll extract the actual implementation in a future step to avoid breaking changes
	st := httpcaddyfile.ServerType{}

	// The httpcaddyfile.ServerType.Setup returns a full config, but we need to merge it
	// into the provided cfg. For now, we'll call it and merge the results.
	httpCfg, warnings, err := st.Setup(blocks, options)
	if err != nil {
		return warnings, err
	}

	// Merge the HTTP config into the provided config
	if err := mergeConfigs(cfg, httpCfg); err != nil {
		return warnings, err
	}

	return warnings, nil
}

// mergeConfigs merges src config into dst config
func mergeConfigs(dst, src *caddy.Config) error {
	// Merge AppsRaw
	if dst.AppsRaw == nil {
		dst.AppsRaw = make(caddy.ModuleMap)
	}
	for name, app := range src.AppsRaw {
		dst.AppsRaw[name] = app
	}

	// Merge Admin (src takes precedence if both exist)
	if src.Admin != nil {
		dst.Admin = src.Admin
	}

	// Merge Storage (src takes precedence)
	if src.StorageRaw != nil {
		dst.StorageRaw = src.StorageRaw
	}

	// Merge Logging
	if src.Logging != nil {
		if dst.Logging == nil {
			dst.Logging = src.Logging
		} else {
			// Merge logs
			if dst.Logging.Logs == nil {
				dst.Logging.Logs = src.Logging.Logs
			} else {
				for name, log := range src.Logging.Logs {
					dst.Logging.Logs[name] = log
				}
			}
		}
	}

	return nil
}
