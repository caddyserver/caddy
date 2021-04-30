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

package caddyevent

import (
	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(EventApp{})
}

// EventApp is a global event system.
type EventApp struct {
}

// CaddyModule returns the Caddy module information.
func (EventApp) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "event",
		New: func() caddy.Module { return new(EventApp) },
	}
}

// Provision sets up the app.
func (app *EventApp) Provision(ctx caddy.Context) error {
	return nil
}

// Validate ensures the app's configuration is valid.
func (app *EventApp) Validate() error {
	return nil
}

// Start runs the app.
func (app *EventApp) Start() error {
	return nil
}

// Stop gracefully shuts down the app.
func (app *EventApp) Stop() error {
	return nil
}

// Interface guards
var (
	_ caddy.App         = (*EventApp)(nil)
	_ caddy.Provisioner = (*EventApp)(nil)
	_ caddy.Validator   = (*EventApp)(nil)
)
