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
	"slices"
	"sort"
	"strings"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
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

		// Apply caddyfile compatibility defaults
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

	// Apply global options from the options map to the builder
	// This mirrors what httpcaddyfile does at the end of Setup()
	if err := applyGlobalOptions(builder, options, &warnings); err != nil {
		return nil, warnings, err
	}

	// Get the config - this finalizes structured apps
	cfg := builder.Config()

	// Process logs after all apps are finalized so we can collect server-specific logs
	if err := processLogs(cfg, options, &warnings); err != nil {
		return nil, warnings, err
	}

	return cfg, warnings, nil
}

// applyGlobalOptions applies values from the options map to the builder.
// This includes admin config, storage, logging, and other global settings.
func applyGlobalOptions(builder *configbuilder.Builder, options map[string]any, warnings *[]caddyconfig.Warning) error {
	// Add any httpcaddyfile.App types from options
	for _, opt := range options {
		if app, ok := opt.(httpcaddyfile.App); ok {
			builder.AddRawApp(app.Name, app.Value)
		}
	}

	// Apply filesystem option
	if filesystems, ok := options["filesystem"].(caddy.Module); ok {
		builder.AddRawApp("caddy.filesystems", caddyconfig.JSON(filesystems, warnings))
	}

	// Apply storage option
	if storageCvtr, ok := options["storage"].(caddy.StorageConverter); ok {
		builder.SetStorage(storageCvtr)
	}

	// Apply admin option
	if adminConfig, ok := options["admin"].(*caddy.AdminConfig); ok && adminConfig != nil {
		builder.SetAdmin(adminConfig)
	}

	// Apply persist_config option
	if pc, ok := options["persist_config"].(string); ok && pc == "off" {
		admin := builder.GetAdmin()
		if admin.Config == nil {
			admin.Config = new(caddy.ConfigSettings)
		}
		falseBool := false
		admin.Config.Persist = &falseBool
	}

	return nil
}

// processLogs collects all custom logs (global and server-specific) and applies them to the config.
// This must run after the config is finalized so we can access the HTTP app.
func processLogs(cfg *caddy.Config, options map[string]any, warnings *[]caddyconfig.Warning) error {
	var customLogs []struct {
		name string
		log  *caddy.CustomLog
	}
	var hasDefaultLog bool

	addCustomLog := func(name string, log *caddy.CustomLog) {
		if name == "" {
			return
		}
		if name == caddy.DefaultLoggerName {
			hasDefaultLog = true
		}
		// Apply debug level if debug is on and no level is set
		if _, ok := options["debug"]; ok && log != nil && log.Level == "" {
			log.Level = zap.DebugLevel.CapitalString()
		}
		customLogs = append(customLogs, struct {
			name string
			log  *caddy.CustomLog
		}{name: name, log: log})
	}

	// Collect global log options from options["log"]
	if options["log"] != nil {
		for _, logValue := range options["log"].([]httpcaddyfile.ConfigValue) {
			nclValue := logValue.Value
			name := httpcaddyfile.GetNamedCustomLogName(nclValue)
			log := httpcaddyfile.GetNamedCustomLogLog(nclValue)
			addCustomLog(name, log)
		}
	}

	// Collect server-specific log options from options["__xcaddyfile_server_logs__"]
	if options["__xcaddyfile_server_logs__"] != nil {
		for _, logValue := range options["__xcaddyfile_server_logs__"].([]httpcaddyfile.ConfigValue) {
			nclValue := logValue.Value
			name := httpcaddyfile.GetNamedCustomLogName(nclValue)
			log := httpcaddyfile.GetNamedCustomLogLog(nclValue)
			addCustomLog(name, log)
		}
	}

	// If no default log was configured but debug is on, add one
	if !hasDefaultLog {
		if _, ok := options["debug"]; ok {
			customLogs = append(customLogs, struct {
				name string
				log  *caddy.CustomLog
			}{
				name: caddy.DefaultLoggerName,
				log: &caddy.CustomLog{
					BaseLog: caddy.BaseLog{Level: zap.DebugLevel.CapitalString()},
				},
			})
		}
	}

	// Apply custom logs to the config
	if len(customLogs) > 0 {
		if cfg.Logging == nil {
			cfg.Logging = &caddy.Logging{
				Logs: make(map[string]*caddy.CustomLog),
			}
		}
		if cfg.Logging.Logs == nil {
			cfg.Logging.Logs = make(map[string]*caddy.CustomLog)
		}

		// Add the default log first if defined
		for _, ncl := range customLogs {
			if ncl.name == caddy.DefaultLoggerName && ncl.log != nil {
				cfg.Logging.Logs[caddy.DefaultLoggerName] = ncl.log
				break
			}
		}

		// Add the rest of the custom logs
		for _, ncl := range customLogs {
			if ncl.log == nil || ncl.name == caddy.DefaultLoggerName {
				continue
			}
			if ncl.name != "" {
				cfg.Logging.Logs[ncl.name] = ncl.log
			}
			// Most users prefer not writing access logs to the default log
			// when they are directed to a file or have special customization
			if ncl.name != caddy.DefaultLoggerName && len(ncl.log.Include) > 0 {
				defaultLog, ok := cfg.Logging.Logs[caddy.DefaultLoggerName]
				if !ok {
					defaultLog = new(caddy.CustomLog)
					cfg.Logging.Logs[caddy.DefaultLoggerName] = defaultLog
				}
				defaultLog.Exclude = append(defaultLog.Exclude, ncl.log.Include...)

				// Avoid duplicates by sorting + compacting
				sort.Strings(defaultLog.Exclude)
				defaultLog.Exclude = slices.Compact(defaultLog.Exclude)
			}
		}
	}

	return nil
}
