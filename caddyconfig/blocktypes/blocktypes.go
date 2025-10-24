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

package blocktypes

import (
	"fmt"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

// BlockTypeSetupFunc is a function that processes server blocks of a specific type
// and mutates the provided Caddy configuration. It receives the config to mutate,
// the server blocks to process, and any global options.
type BlockTypeSetupFunc func(cfg *caddy.Config, blocks []caddyfile.ServerBlock, options map[string]any) ([]caddyconfig.Warning, error)

var (
	registeredBlockTypes = make(map[string]BlockTypeSetupFunc)
	blockTypesMu         sync.RWMutex
)

// RegisterBlockType registers a block type handler with the given name.
// This allows the block type to be used in xcaddyfile configurations with [name] syntax.
// For example, RegisterBlockType("http", setupFunc) allows [http] blocks.
//
// Block type handlers are responsible for parsing their specific block types
// and mutating the provided caddy.Config accordingly.
func RegisterBlockType(name string, setupFunc BlockTypeSetupFunc) {
	blockTypesMu.Lock()
	defer blockTypesMu.Unlock()

	if _, exists := registeredBlockTypes[name]; exists {
		panic(fmt.Sprintf("block type %s already registered", name))
	}

	registeredBlockTypes[name] = setupFunc
}

// GetBlockType retrieves a registered block type handler by name.
// Returns the handler function and true if found, nil and false otherwise.
func GetBlockType(name string) (BlockTypeSetupFunc, bool) {
	blockTypesMu.RLock()
	defer blockTypesMu.RUnlock()

	handler, exists := registeredBlockTypes[name]
	return handler, exists
}

// RegisteredBlockTypes returns a list of all registered block type names.
func RegisteredBlockTypes() []string {
	blockTypesMu.RLock()
	defer blockTypesMu.RUnlock()

	names := make([]string, 0, len(registeredBlockTypes))
	for name := range registeredBlockTypes {
		names = append(names, name)
	}
	return names
}
