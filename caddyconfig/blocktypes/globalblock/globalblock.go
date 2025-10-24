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

package globalblock

import (
	"fmt"
	"reflect"
	"sort"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/blocktypes"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddypki"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

func init() {
	blocktypes.RegisterBlockType("global", Setup)
}

// Setup processes global configuration blocks and mutates the provided Caddy config.
// Global blocks configure server-wide options like admin API, logging, storage, etc.
func Setup(cfg *caddy.Config, blocks []caddyfile.ServerBlock, options map[string]any) ([]caddyconfig.Warning, error) {
	var warnings []caddyconfig.Warning

	// Process each global block
	for _, block := range blocks {
		// Global blocks should not have keys (addresses)
		if len(block.Keys) > 0 {
			return warnings, fmt.Errorf("global blocks should not have addresses/keys")
		}

		// Process each directive in the global block
		for _, segment := range block.Segments {
			opt := segment.Directive()
			var val any
			var err error
			disp := caddyfile.NewDispenser(segment)

			// Look up the registered global option handler
			optFunc, ok := httpcaddyfile.GetGlobalOption(opt)
			if !ok {
				tkn := segment[0]
				return warnings, fmt.Errorf("%s:%d: unrecognized global option: %s", tkn.File, tkn.Line, opt)
			}

			val, err = optFunc(disp, options[opt])
			if err != nil {
				return warnings, fmt.Errorf("parsing caddyfile tokens for '%s': %v", opt, err)
			}

			// Some options need to be folded/appended rather than replaced
			if folder := httpcaddyfile.GetGlobalOptionFolder(opt); folder != nil {
				folded, err := folder.Fold(options[opt], val)
				if err != nil {
					return warnings, err
				}
				options[opt] = folded
				continue
			}

			options[opt] = val
		}
	}

	// Sort servers options by listener address if present
	if serverOpts, ok := options["servers"].([]httpcaddyfile.ServerOptions); ok {
		sort.Slice(serverOpts, func(i, j int) bool {
			return len(serverOpts[i].ListenerAddress) > len(serverOpts[j].ListenerAddress)
		})

		// Reject duplicate listener addresses
		seen := make(map[string]bool)
		for _, entry := range serverOpts {
			if _, alreadySeen := seen[entry.ListenerAddress]; alreadySeen {
				return warnings, fmt.Errorf("cannot have 'servers' global options with duplicate listener addresses: %s", entry.ListenerAddress)
			}
			seen[entry.ListenerAddress] = true
		}

		// Store the sorted options back
		options["servers"] = serverOpts
	}

	// Now apply the global options to the config
	if err := applyGlobalOptionsToConfig(cfg, options, &warnings); err != nil {
		return warnings, err
	}

	return warnings, nil
}

// applyGlobalOptionsToConfig applies the parsed global options to the Caddy config
func applyGlobalOptionsToConfig(cfg *caddy.Config, options map[string]any, warnings *[]caddyconfig.Warning) error {
	// Apply storage configuration
	if storageCvtr, ok := options["storage"].(caddy.StorageConverter); ok {
		cfg.StorageRaw = caddyconfig.JSONModuleObject(storageCvtr,
			"module",
			storageCvtr.(caddy.Module).CaddyModule().ID.Name(),
			warnings)
	}

	// Apply admin configuration
	if adminConfig, ok := options["admin"].(*caddy.AdminConfig); ok && adminConfig != nil {
		cfg.Admin = adminConfig
	}

	// Apply persist_config option
	if pc, ok := options["persist_config"].(string); ok && pc == "off" {
		if cfg.Admin == nil {
			cfg.Admin = new(caddy.AdminConfig)
		}
		if cfg.Admin.Config == nil {
			cfg.Admin.Config = new(caddy.ConfigSettings)
		}
		cfg.Admin.Config.Persist = new(bool)
	}

	// Apply filesystem configuration
	if filesystems, ok := options["filesystem"].(caddy.Module); ok {
		if cfg.AppsRaw == nil {
			cfg.AppsRaw = make(caddy.ModuleMap)
		}
		cfg.AppsRaw["caddy.filesystems"] = caddyconfig.JSON(filesystems, warnings)
	}

	// Loop through configured options and insert any httpcaddyfile.App instances
	for _, opt := range options {
		if app, ok := opt.(httpcaddyfile.App); ok {
			if cfg.AppsRaw == nil {
				cfg.AppsRaw = make(caddy.ModuleMap)
			}
			cfg.AppsRaw[app.Name] = app.Value
		}
	}

	// Note: TLS and PKI apps are typically configured by the HTTP block type,
	// but we ensure they exist with default values if not already set
	if cfg.AppsRaw == nil {
		cfg.AppsRaw = make(caddy.ModuleMap)
	}

	// Only initialize TLS app if not already present
	if _, exists := cfg.AppsRaw["tls"]; !exists {
		tlsApp := &caddytls.TLS{CertificatesRaw: make(caddy.ModuleMap)}
		if !reflect.DeepEqual(tlsApp, &caddytls.TLS{CertificatesRaw: make(caddy.ModuleMap)}) {
			cfg.AppsRaw["tls"] = caddyconfig.JSON(tlsApp, warnings)
		}
	}

	// Only initialize PKI app if not already present
	if _, exists := cfg.AppsRaw["pki"]; !exists {
		pkiApp := &caddypki.PKI{CAs: make(map[string]*caddypki.CA)}
		if !reflect.DeepEqual(pkiApp, &caddypki.PKI{CAs: make(map[string]*caddypki.CA)}) {
			cfg.AppsRaw["pki"] = caddyconfig.JSON(pkiApp, warnings)
		}
	}

	return nil
}
