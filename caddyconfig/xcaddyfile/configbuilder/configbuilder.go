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

package configbuilder

import (
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
)

// Builder provides methods for safely building a Caddy configuration
// by accumulating apps, admin config, logging, storage, etc.
// It prevents common errors like duplicate app names.
type Builder struct {
	config   *caddy.Config
	warnings *[]caddyconfig.Warning
	// apps stores structured app configs before marshaling
	// Multiple blocks can contribute to the same app
	apps map[string]any
}

// New creates a new config builder with an empty configuration.
func New() *Builder {
	warnings := []caddyconfig.Warning{}
	return &Builder{
		config: &caddy.Config{
			AppsRaw: make(caddy.ModuleMap),
		},
		warnings: &warnings,
		apps:     make(map[string]any),
	}
}

// Config returns the built configuration.
// This automatically finalizes any structured apps that haven't been marshaled yet.
func (b *Builder) Config() *caddy.Config {
	b.finalize()
	return b.config
}

// Warnings returns the accumulated warnings.
func (b *Builder) Warnings() []caddyconfig.Warning {
	return *b.warnings
}

// AddWarning adds a warning to the builder.
func (b *Builder) AddWarning(message string) {
	*b.warnings = append(*b.warnings, caddyconfig.Warning{
		Message: message,
	})
}

// GetApp retrieves a structured app config by name.
// Returns a pointer to the app and true if found, nil and false otherwise.
// The returned value can be type-asserted to the specific app type.
// Blocks should use this to get an existing app before modifying it.
func (b *Builder) GetApp(name string) (any, bool) {
	app, ok := b.apps[name]
	return app, ok
}

// GetTypedApp retrieves a structured app config by name with the correct type.
// Returns a pointer to the app and true if found, nil and false otherwise.
// This is a type-safe alternative to GetApp that uses generics.
// Example: httpApp, ok := builder.GetTypedApp[caddyhttp.App]("http")
func GetTypedApp[T any](b *Builder, name string) (*T, bool) {
	app, ok := b.apps[name]
	if !ok {
		return nil, false
	}
	typedApp, ok := app.(*T)
	return typedApp, ok
}

// CreateApp stores a new structured app config by name.
// Returns an error if an app with this name already exists.
// Blocks that want to modify an existing app should use GetApp() first.
func (b *Builder) CreateApp(name string, app any) error {
	if _, exists := b.apps[name]; exists {
		return fmt.Errorf("app '%s' already exists", name)
	}
	b.apps[name] = app
	return nil
}

// UpdateApp replaces an existing app config or creates it if it doesn't exist.
// This is useful for blocks that need to replace the entire app structure.
func (b *Builder) UpdateApp(name string, app any) {
	b.apps[name] = app
}

// finalize marshals all structured apps to JSON and adds them to the config.
// This is called automatically by Config().
func (b *Builder) finalize() {
	for name, app := range b.apps {
		b.addApp(name, app)
	}
	// Clear apps after finalizing so we don't re-add them if Config() is called again
	b.apps = make(map[string]any)
}

// addApp is an internal method to add an app to the configuration by marshaling it to JSON.
// If an app with the same name already exists, a warning is added and the duplicate is ignored.
func (b *Builder) addApp(name string, val any) {
	if b.config.AppsRaw == nil {
		b.config.AppsRaw = make(caddy.ModuleMap)
	}

	if _, exists := b.config.AppsRaw[name]; exists {
		b.AddWarning(fmt.Sprintf("app '%s' already exists in configuration, ignoring duplicate declaration", name))
		return
	}

	b.config.AppsRaw[name] = caddyconfig.JSON(val, b.warnings)
}

// SetAdmin sets the admin configuration.
// If admin config already exists, it will be replaced.
func (b *Builder) SetAdmin(admin *caddy.AdminConfig) {
	b.config.Admin = admin
}

// SetStorage sets the storage configuration from a StorageConverter.
// If storage config already exists, it will be replaced.
func (b *Builder) SetStorage(storage caddy.StorageConverter) {
	b.config.StorageRaw = caddyconfig.JSONModuleObject(
		storage,
		"module",
		storage.(caddy.Module).CaddyModule().ID.Name(),
		b.warnings,
	)
}

// SetDefaultLogger sets the default logger configuration.
func (b *Builder) SetDefaultLogger(log *caddy.CustomLog) {
	if b.config.Logging == nil {
		b.config.Logging = &caddy.Logging{
			Logs: make(map[string]*caddy.CustomLog),
		}
	}
	if b.config.Logging.Logs == nil {
		b.config.Logging.Logs = make(map[string]*caddy.CustomLog)
	}
	b.config.Logging.Logs[caddy.DefaultLoggerName] = log
}

// SetLogger sets a named logger configuration.
func (b *Builder) SetLogger(name string, log *caddy.CustomLog) {
	if b.config.Logging == nil {
		b.config.Logging = &caddy.Logging{
			Logs: make(map[string]*caddy.CustomLog),
		}
	}
	if b.config.Logging.Logs == nil {
		b.config.Logging.Logs = make(map[string]*caddy.CustomLog)
	}
	b.config.Logging.Logs[name] = log
}
