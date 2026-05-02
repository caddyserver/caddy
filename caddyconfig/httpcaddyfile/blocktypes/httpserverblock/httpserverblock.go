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

package httpserverblock

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/configbuilder"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile/blocktypes"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddypki"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

func init() {
	blocktypes.RegisterChildBlockType("http.server", "global", setup)
}

// extractServerBlocks converts raw caddyfile blocks to httpcaddyfile serverBlock format
func extractServerBlocks(inputBlocks []caddyfile.ServerBlock, warnings []caddyconfig.Warning) ([]httpcaddyfile.ServerBlock, []caddyconfig.Warning, error) {
	serverBlocks := make([]httpcaddyfile.ServerBlock, 0, len(inputBlocks))
	for _, sblock := range inputBlocks {
		for j, k := range sblock.Keys {
			if j == 0 && strings.HasPrefix(k.Text, "@") {
				return nil, warnings, fmt.Errorf("%s:%d: cannot define a matcher outside of a site block: '%s'", k.File, k.Line, k.Text)
			}
			if httpcaddyfile.DirectiveIsRegistered(k.Text) {
				return nil, warnings, fmt.Errorf("%s:%d: parsed '%s' as a site address, but it is a known directive; directives must appear in a site block", k.File, k.Line, k.Text)
			}
		}
		serverBlocks = append(serverBlocks, httpcaddyfile.ServerBlock{
			Block: sblock,
			Pile:  make(map[string][]httpcaddyfile.ConfigValue),
		})
	}
	return serverBlocks, warnings, nil
}

// setup processes [http.server] blocks using the httpcaddyfile adapter.
// This leverages all existing HTTP configuration logic.
// The [global] block should have been processed first to set up global options.
func setup(builder *configbuilder.Builder, blocks []caddyfile.ServerBlock, options map[string]any) ([]caddyconfig.Warning, error) {
	var warnings []caddyconfig.Warning

	// Extract server blocks with validation
	serverBlocks, warnings, err := extractServerBlocks(blocks, warnings)
	if err != nil {
		return warnings, err
	}

	// Use httpcaddyfile.BuildServersAndPairings to build servers and pairings
	servers, pairings, metrics, warnings, err := httpcaddyfile.BuildServersAndPairings(serverBlocks, options, warnings)
	if err != nil {
		return warnings, err
	}

	// Collect server-specific custom logs for xcaddyfiletype to process later
	// Use a unique key name to avoid conflicts with other options
	serverLogs := httpcaddyfile.CollectServerLogs(pairings)
	if len(serverLogs) > 0 {
		options["__xcaddyfile_server_logs__"] = serverLogs
	}

	// Construct the HTTP app from the servers
	// Use options from [global] block if they were set
	httpApp := &caddyhttp.App{
		HTTPPort:      httpcaddyfile.TryInt(options["http_port"], &warnings),
		HTTPSPort:     httpcaddyfile.TryInt(options["https_port"], &warnings),
		GracePeriod:   httpcaddyfile.TryDuration(options["grace_period"], &warnings),
		ShutdownDelay: httpcaddyfile.TryDuration(options["shutdown_delay"], &warnings),
		Metrics:       metrics,
		Servers:       servers,
	}

	// Create the HTTP app (should be the first time, since [global] doesn't create it)
	if err := builder.CreateApp("http", httpApp); err != nil {
		return warnings, err
	}

	// Build TLS app using the pairings
	tlsApp, tlsWarnings, err := httpcaddyfile.BuildTLSApp(pairings, options, warnings)
	if err != nil {
		return append(warnings, tlsWarnings...), err
	}
	warnings = append(warnings, tlsWarnings...)
	// Only add TLS app if it's not empty (has certificates or automation policies)
	if tlsApp != nil && (!reflect.DeepEqual(tlsApp, &caddytls.TLS{CertificatesRaw: make(caddy.ModuleMap)})) {
		if err := builder.CreateApp("tls", tlsApp); err != nil {
			return warnings, err
		}
	}

	// Build PKI app using the pairings
	pkiApp, pkiWarnings, err := httpcaddyfile.BuildPKIApp(pairings, options, warnings)
	if err != nil {
		return append(warnings, pkiWarnings...), err
	}
	warnings = append(warnings, pkiWarnings...)
	// Only add PKI app if it's not empty (has CAs)
	if pkiApp != nil && (!reflect.DeepEqual(pkiApp, &caddypki.PKI{CAs: make(map[string]*caddypki.CA)})) {
		if err := builder.CreateApp("pki", pkiApp); err != nil {
			return warnings, err
		}
	}

	return warnings, nil
}
