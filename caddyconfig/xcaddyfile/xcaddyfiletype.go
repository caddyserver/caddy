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
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/xcaddyfile/blocktypes"
	_ "github.com/caddyserver/caddy/v2/caddyconfig/xcaddyfile/blocktypes/globalblock"
	_ "github.com/caddyserver/caddy/v2/caddyconfig/xcaddyfile/blocktypes/httpserverblock"
	"github.com/caddyserver/caddy/v2/caddyconfig/xcaddyfile/configbuilder"
)

func init() {
	caddyconfig.RegisterAdapter("xcaddyfile", caddyfile.Adapter{ServerType: XCaddyfileType{}})
}

// XCaddyfileType is a Caddy config adapter that processes extended Caddyfiles
// with explicit block type declarations using [type] syntax. For backwards
// compatibility with standard Caddyfile, it also supports implicit types:
// - First block with no keys is treated as [global]
// - Blocks without [type] are treated as [http.server]
type XCaddyfileType struct{}

// extractBlockType extracts the block type from a server block if it has
// explicit [type] syntax. Returns empty string if no explicit type is found.
func extractBlockType(sblock *caddyfile.ServerBlock) (blockType string, err error) {
	if len(sblock.Keys) == 0 {
		return "", nil
	}

	firstKey := sblock.Keys[0].Text

	// Check if this uses explicit [type] syntax
	if strings.HasPrefix(firstKey, "[") && strings.HasSuffix(firstKey, "]") {
		// Extract the block type name
		blockType = strings.TrimSuffix(strings.TrimPrefix(firstKey, "["), "]")
		if blockType == "" {
			return "", fmt.Errorf("%s:%d: empty block type declaration []",
				sblock.Keys[0].File, sblock.Keys[0].Line)
		}

		// Remove the [type] token from the keys
		sblock.Keys = sblock.Keys[1:]
		return blockType, nil
	}

	// No explicit type
	return "", nil
}

// Setup processes the server blocks from an xcaddyfile and builds a complete Caddy configuration.
// It expects all server blocks to have a block type prefix like [http], [caddy], [layer4], etc.
func (XCaddyfileType) Setup(
	inputServerBlocks []caddyfile.ServerBlock,
	options map[string]any,
) (*caddy.Config, []caddyconfig.Warning, error) {
	var warnings []caddyconfig.Warning

	// Track block types in order of appearance
	type blockGroup struct {
		blockType string
		blocks    []caddyfile.ServerBlock
	}
	var orderedBlocks []blockGroup
	seenTypes := make(map[string]int) // maps block type to index in orderedBlocks

	for i, sblock := range inputServerBlocks {
		// Extract explicit block type if present
		blockType, err := extractBlockType(&sblock)
		if err != nil {
			return nil, warnings, err
		}

		// Apply backwards compatibility defaults
		if blockType == "" {
			// First block with no keys is treated as global config
			if i == 0 && len(sblock.Keys) == 0 {
				blockType = "global"
			} else {
				// Default to http.server for backwards compatibility with Caddyfile
				blockType = "http.server"
			}
		}

		// Add to the appropriate group, preserving order
		if idx, seen := seenTypes[blockType]; seen {
			// Append to existing group
			orderedBlocks[idx].blocks = append(orderedBlocks[idx].blocks, sblock)
		} else {
			// Create new group
			seenTypes[blockType] = len(orderedBlocks)
			orderedBlocks = append(orderedBlocks, blockGroup{
				blockType: blockType,
				blocks:    []caddyfile.ServerBlock{sblock},
			})
		}
	}

	// Create the config builder
	builder := configbuilder.New()

	// Process block types in the order they appear, but ensure parent blocks
	// are processed before their children
	processed := make(map[string]bool)

	var processBlock func(blockType string) error
	processBlock = func(blockType string) error {
		if processed[blockType] {
			return nil
		}

		// Get block type info to check for parent
		info, ok := blocktypes.GetBlockTypeInfo(blockType)
		if !ok {
			available := blocktypes.RegisteredBlockTypes()
			return fmt.Errorf("block type '%s' is not registered; available types: %v", blockType, available)
		}

		// Process parent first if it exists
		if info.Parent != "" {
			if err := processBlock(info.Parent); err != nil {
				return err
			}
		}

		// Find and process this block type's blocks
		for _, group := range orderedBlocks {
			if group.blockType == blockType {
				blockWarnings, err := info.SetupFunc(builder, group.blocks, options)
				warnings = append(warnings, blockWarnings...)
				if err != nil {
					return fmt.Errorf("processing [%s] blocks: %w", blockType, err)
				}
				processed[blockType] = true
				break
			}
		}

		return nil
	}

	// Process each block type
	for _, group := range orderedBlocks {
		if err := processBlock(group.blockType); err != nil {
			return nil, warnings, err
		}
	}

	// Config() automatically finalizes structured apps
	return builder.Config(), warnings, nil
}
