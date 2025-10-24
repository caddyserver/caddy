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
	"reflect"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/xcaddyfile/blocktypes"
	"github.com/caddyserver/caddy/v2/caddyconfig/xcaddyfile/configbuilder"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddypki"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

func init() {
	blocktypes.RegisterChildBlockType("http.server", "global", Setup)
}

// Setup processes [http.server] blocks using the httpcaddyfile adapter.
// This allows xcaddyfile to leverage all existing HTTP configuration logic.
// The [global] block should have created the HTTP app with options in context.
func Setup(builder *configbuilder.Builder, blocks []caddyfile.ServerBlock, options map[string]any) ([]caddyconfig.Warning, error) {
	// Use httpcaddyfile.BuildServersOnly which builds servers and returns pairings
	// needed for TLS/PKI apps
	serversApp, pairings, warnings, err := httpcaddyfile.BuildServersOnly(blocks, options)
	if err != nil {
		return warnings, err
	}

	// Get or create the HTTP app (may have been created by [global] block)
	var finalApp *caddyhttp.App
	if existingApp, ok := configbuilder.GetTypedApp[caddyhttp.App](builder, "http"); ok {
		// Merge servers into existing app from global block
		// The global block already set app-level options like grace_period, https_port
		finalApp = existingApp
		if finalApp.Servers == nil {
			finalApp.Servers = make(map[string]*caddyhttp.Server)
		}
		for name, server := range serversApp.Servers {
			finalApp.Servers[name] = server
		}
		// Also copy app-level settings from httpcaddyfile if not set by global
		if finalApp.HTTPPort == 0 && serversApp.HTTPPort != 0 {
			finalApp.HTTPPort = serversApp.HTTPPort
		}
		if finalApp.HTTPSPort == 0 && serversApp.HTTPSPort != 0 {
			finalApp.HTTPSPort = serversApp.HTTPSPort
		}
		if finalApp.GracePeriod == 0 && serversApp.GracePeriod != 0 {
			finalApp.GracePeriod = serversApp.GracePeriod
		}
		if finalApp.ShutdownDelay == 0 && serversApp.ShutdownDelay != 0 {
			finalApp.ShutdownDelay = serversApp.ShutdownDelay
		}
		if finalApp.Metrics == nil && serversApp.Metrics != nil {
			finalApp.Metrics = serversApp.Metrics
		}
		// Update the app with merged servers
		builder.UpdateApp("http", finalApp)
	} else {
		// No global block, use the complete app from httpcaddyfile
		finalApp = serversApp
		// Create the app since it doesn't exist yet
		if err := builder.CreateApp("http", finalApp); err != nil {
			return warnings, err
		}
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
			// TLS app might already exist, update it instead
			builder.UpdateApp("tls", tlsApp)
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
			// PKI app might already exist, update it instead
			builder.UpdateApp("pki", pkiApp)
		}
	}

	return warnings, nil
}
