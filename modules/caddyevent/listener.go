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

// ListenerFunc is a function that can handle a dispatched event.
type ListenerFunc func(e Event) error

// Handle runs the event listener on the given event.
func (fn ListenerFunc) Handle(e Event) error {
	return fn(e)
}

// Priority is a factor by which event listeners can be sorted.
type Priority int

// ListenerEntry is a wrapper to allow associating a listener function
// to a priority factor when registering event subscribers and listeners.
type ListenerEntry struct {
	Listener ListenerFunc
	Priority Priority
}

// Subscriber defines an interface for modules that wish
// to subscribe to dispatched events.
type Subscriber interface {
	// SubscribedEvents returns a map of event IDs that
	// this subscriber can handle, to the function that
	// handles the event.
	SubscribedEvents() map[caddy.ModuleID]ListenerEntry
}
