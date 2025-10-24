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

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/xcaddyfile/blocktypes"
	"github.com/caddyserver/caddy/v2/caddyconfig/xcaddyfile/configbuilder"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	blocktypes.RegisterBlockType("global", Setup)
}

// Setup processes [global] configuration blocks which configure both core Caddy settings
// (admin API, logging, storage) and HTTP app-level settings (grace_period, https_port, etc.).
// This maintains backwards compatibility with standard Caddyfile global options.
func Setup(builder *configbuilder.Builder, blocks []caddyfile.ServerBlock, options map[string]any) ([]caddyconfig.Warning, error) {
	var warnings []caddyconfig.Warning

	httpApp := &caddyhttp.App{}
	hasHttpOptions := false

	// Process each global block
	for _, block := range blocks {
		// Global blocks should not have keys (addresses)
		if len(block.Keys) > 0 {
			return warnings, fmt.Errorf("[global] blocks should not have addresses/keys")
		}

		// Process each directive in the global block
		for _, segment := range block.Segments {
			directive := segment.Directive()
			disp := caddyfile.NewDispenser(segment)

			switch directive {
			case "admin":
				adminConfig, err := parseAdmin(disp)
				if err != nil {
					return warnings, fmt.Errorf("parsing admin: %v", err)
				}
				builder.SetAdmin(adminConfig)

			case "log":
				log, err := parseLogging(disp)
				if err != nil {
					return warnings, fmt.Errorf("parsing log: %v", err)
				}
				builder.SetDefaultLogger(log)

			case "storage":
				storage, err := parseStorage(disp)
				if err != nil {
					return warnings, fmt.Errorf("parsing storage: %v", err)
				}
				builder.SetStorage(storage)

			default:
				// Try to use httpcaddyfile's global options for HTTP app settings
				if handler, ok := httpcaddyfile.GetGlobalOption(directive); ok {
					val, err := handler(disp, nil)
					if err != nil {
						return warnings, fmt.Errorf("parsing %s: %v", directive, err)
					}

					// Store in options for http.server blocks to access
					options[directive] = val
					hasHttpOptions = true
				} else {
					return warnings, fmt.Errorf("%s:%d: unrecognized [global] directive: %s",
						segment[0].File, segment[0].Line, directive)
				}
			}
		}
	}

	// Create HTTP app for http.server blocks to modify
	// Don't marshal it yet - let child blocks add servers first
	if hasHttpOptions {
		if err := builder.CreateApp("http", httpApp); err != nil {
			return warnings, err
		}
	}

	return warnings, nil
}

// parseAdmin parses the admin directive
func parseAdmin(d *caddyfile.Dispenser) (*caddy.AdminConfig, error) {
	d.Next() // consume directive name

	admin := new(caddy.AdminConfig)

	for d.NextArg() {
		switch d.Val() {
		case "off":
			admin.Disabled = true

		default:
			// Assume it's a listen address
			admin.Listen = d.Val()
		}
	}

	return admin, nil
}

// parseLogging parses the log directive
func parseLogging(d *caddyfile.Dispenser) (*caddy.CustomLog, error) {
	d.Next() // consume directive name

	log := &caddy.CustomLog{}

	// Simple log level setting for now
	for d.NextArg() {
		level := d.Val()
		log.BaseLog = caddy.BaseLog{Level: level}
	}

	return log, nil
}

// parseStorage parses the storage directive
func parseStorage(d *caddyfile.Dispenser) (caddy.StorageConverter, error) {
	d.Next() // consume directive name

	// Use the caddyfile module unmarshaling
	if !d.NextArg() {
		return nil, d.ArgErr()
	}

	modID := "caddy.storage." + d.Val()
	unm, err := caddyfile.UnmarshalModule(d, modID)
	if err != nil {
		return nil, err
	}

	storage, ok := unm.(caddy.StorageConverter)
	if !ok {
		return nil, fmt.Errorf("module %s (%T) is not a storage module", modID, unm)
	}

	return storage, nil
}
