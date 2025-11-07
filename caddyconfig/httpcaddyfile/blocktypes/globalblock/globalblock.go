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

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/configbuilder"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile/blocktypes"
)

func init() {
	blocktypes.RegisterBlockType("global", Setup)
}

// global configuration blocks which store global options
// (http_port, https_port, grace_period, etc.) in options for other block parsers to use.
func Setup(builder *configbuilder.Builder, blocks []caddyfile.ServerBlock, options map[string]any) ([]caddyconfig.Warning, error) {
	var warnings []caddyconfig.Warning

	// Process each global block
	for _, block := range blocks {
		// Global blocks should not have keys
		if len(block.Keys) > 0 {
			return warnings, fmt.Errorf("[global] blocks should not have keys")
		}

		// Use httpcaddyfile's EvaluateGlobalOptions for all global options
		if err := httpcaddyfile.EvaluateGlobalOptions(block.Segments, options); err != nil {
			return warnings, err
		}
	}

	return warnings, nil
}
