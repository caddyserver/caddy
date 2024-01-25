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

// Package eventsconfig is for configuring caddyevents.App with the
// Caddyfile. This code can't be in the caddyevents package because
// the httpcaddyfile package imports caddyhttp, which imports
// caddyevents: hence, it creates an import cycle.
package eventsconfig

import (
	"encoding/json"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyevents"
)

func init() {
	httpcaddyfile.RegisterGlobalOption("events", parseApp)
}

// parseApp configures the "events" global option from Caddyfile to set up the events app.
// Syntax:
//
//	events {
//		on <event> <handler_module...>
//	}
//
// If <event> is *, then it will bind to all events.
func parseApp(d *caddyfile.Dispenser, _ any) (any, error) {
	d.Next() // consume option name
	app := new(caddyevents.App)
	for d.NextBlock(0) {
		switch d.Val() {
		case "on":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			eventName := d.Val()
			if eventName == "*" {
				eventName = ""
			}

			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			handlerName := d.Val()
			modID := "events.handlers." + handlerName
			unm, err := caddyfile.UnmarshalModule(d, modID)
			if err != nil {
				return nil, err
			}

			app.Subscriptions = append(app.Subscriptions, &caddyevents.Subscription{
				Events: []string{eventName},
				HandlersRaw: []json.RawMessage{
					caddyconfig.JSONModuleObject(unm, "handler", handlerName, nil),
				},
			})

		default:
			return nil, d.ArgErr()
		}
	}

	return httpcaddyfile.App{
		Name:  "events",
		Value: caddyconfig.JSON(app, nil),
	}, nil
}
