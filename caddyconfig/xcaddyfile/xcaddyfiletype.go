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

package xcaddyfile

import (
	"fmt"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/blocktypes"
	_ "github.com/caddyserver/caddy/v2/caddyconfig/blocktypes/globalblock"
	_ "github.com/caddyserver/caddy/v2/caddyconfig/blocktypes/httpblock"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func init() {
	caddyconfig.RegisterAdapter("xcaddyfile", caddyfile.Adapter{ServerType: XCaddyfileType{}})
}

// XCaddyfileType is a Caddy config adapter that processes extended Caddyfiles
// with explicit block type declarations using [type] syntax. Unlike the standard
// Caddyfile adapter, xcaddyfile requires all blocks to specify their type explicitly.
type XCaddyfileType struct{}

// Setup processes the server blocks from an xcaddyfile and builds a complete Caddy configuration.
// It expects all server blocks to have a block type prefix like [http], [global], [layer4], etc.
func (XCaddyfileType) Setup(
	inputServerBlocks []caddyfile.ServerBlock,
	options map[string]any,
) (*caddy.Config, []caddyconfig.Warning, error) {
	var warnings []caddyconfig.Warning

	// Group server blocks by their block type
	blocksByType := make(map[string][]caddyfile.ServerBlock)

	for _, sblock := range inputServerBlocks {
		// Every block must have at least one key, and the first key must be the block type
		if len(sblock.Keys) == 0 {
			return nil, warnings, fmt.Errorf("xcaddyfile requires all blocks to have a [type] declaration")
		}

		// Extract the block type from the first key
		firstKey := sblock.Keys[0].Text
		if !strings.HasPrefix(firstKey, "[") || !strings.HasSuffix(firstKey, "]") {
			return nil, warnings, fmt.Errorf("%s:%d: xcaddyfile requires block type declaration like [http] or [global], got: %s",
				sblock.Keys[0].File, sblock.Keys[0].Line, firstKey)
		}

		// Extract the block type name
		blockType := strings.TrimSuffix(strings.TrimPrefix(firstKey, "["), "]")
		if blockType == "" {
			return nil, warnings, fmt.Errorf("%s:%d: empty block type declaration []",
				sblock.Keys[0].File, sblock.Keys[0].Line)
		}

		// Remove the [type] token from the keys
		sblock.Keys = sblock.Keys[1:]

		// Add to the group for this block type
		blocksByType[blockType] = append(blocksByType[blockType], sblock)
	}

	// Create the config that will be mutated by each block type handler
	cfg := &caddy.Config{
		AppsRaw: make(caddy.ModuleMap),
	}

	// Process each block type group
	// Process [global] blocks first if they exist, since they set up global options
	if globalBlocks, hasGlobal := blocksByType["global"]; hasGlobal {
		handler, ok := blocktypes.GetBlockType("global")
		if !ok {
			return nil, warnings, fmt.Errorf("block type 'global' is not registered")
		}

		blockWarnings, err := handler(cfg, globalBlocks, options)
		warnings = append(warnings, blockWarnings...)
		if err != nil {
			return nil, warnings, fmt.Errorf("processing [global] blocks: %w", err)
		}

		delete(blocksByType, "global") // Remove so we don't process it again
	}

	// Process all other block types
	for blockType, blocks := range blocksByType {
		handler, ok := blocktypes.GetBlockType(blockType)
		if !ok {
			// Provide helpful error message with available block types
			available := blocktypes.RegisteredBlockTypes()
			return nil, warnings, fmt.Errorf("block type '%s' is not registered; available types: %v", blockType, available)
		}

		blockWarnings, err := handler(cfg, blocks, options)
		warnings = append(warnings, blockWarnings...)
		if err != nil {
			return nil, warnings, fmt.Errorf("processing [%s] blocks: %w", blockType, err)
		}
	}

	return cfg, warnings, nil
}
