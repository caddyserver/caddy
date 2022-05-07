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

package reverseproxy

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyevent"
)

// ActiveUnhealthyEvent is dispatched when an upstream
// became unhealthy via active health checks, when it was
// previously healthy.
type ActiveUnhealthyEvent struct {
	caddyevent.GenericEvent
}

func NewActiveUnhealthyEvent(hostAddr string) *ActiveUnhealthyEvent {
	event := new(ActiveUnhealthyEvent)
	event.SetID(caddy.ModuleID("http.handlers.reverse_proxy.event.active_unhealthy"))
	event.Set("host", hostAddr)
	return event
}

func (e ActiveUnhealthyEvent) GetHost() string {
	return e.Get("host").(string)
}

// ActiveUnhealthyEvent is dispatched when an upstream
// became healthy via active health checks, when it was
// previously unhealthy.
type ActiveHealthyEvent struct {
	caddyevent.GenericEvent
}

func NewActiveHealthyEvent(hostAddr string) *ActiveHealthyEvent {
	event := new(ActiveHealthyEvent)
	event.SetID(caddy.ModuleID("http.handlers.reverse_proxy.event.active_healthy"))
	event.Set("host", hostAddr)
	return event
}

func (e ActiveHealthyEvent) GetHost() string {
	return e.Get("host").(string)
}
