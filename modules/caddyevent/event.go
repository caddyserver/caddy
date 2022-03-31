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

// DataMap is a key-value pair map.
type DataMap map[string]interface{}

// Event interface
type Event interface {
	// Get the module ID of the event.
	ID() caddy.ModuleID

	// Get an item from the data map by key.
	Get(key string) interface{}

	// Set an item in the data map by key.
	Set(key string, val interface{})

	// Get the entire data map.
	Data() DataMap

	// Replace the entire data map.
	SetData(DataMap)

	// StopPropagation sets the event to no longer propagate
	// to subsequent event listeners.
	StopPropagation(bool)

	// IsPropagationStopped returns whether the event is set
	// to no longer propagate. In other words, this is
	// whether the event dispatcher should stop handling
	// this event and skip passing it to any subsequent
	// event listeners.
	IsPropagationStopped() bool
}

// GenericEvent a generic event, which can be used
// with composition to provide baseline functionality
// for custom events.
type GenericEvent struct {
	// The module ID of the event.
	id caddy.ModuleID

	// Key-value data pairs of contextual information.
	data DataMap

	// Whether the event handling should be aborted,
	// and no event handlers should be called after
	// this point. Allows for "middleware chain" type
	// of functionality.
	propagationStopped bool
}

// NewGeneric creates a generic event instance.
func NewGeneric(id caddy.ModuleID, data DataMap) *GenericEvent {
	if data == nil {
		data = make(DataMap)
	}

	return &GenericEvent{
		id:   id,
		data: data,
	}
}

// SetID sets the module ID of the event.
func (e *GenericEvent) SetID(id caddy.ModuleID) {
	e.id = id
}

// Get the module ID of the event.
func (e *GenericEvent) ID() caddy.ModuleID {
	return e.id
}

// Get an item from the data map by key.
func (e *GenericEvent) Get(key string) interface{} {
	if v, ok := e.data[key]; ok {
		return v
	}

	return nil
}

// Set an item in the data map by key.
func (e *GenericEvent) Set(key string, val interface{}) {
	if e.data == nil {
		e.data = make(DataMap)
	}

	e.data[key] = val
}

// Data returns the entire data map.
func (e *GenericEvent) Data() DataMap {
	return e.data
}

// SetData overwrites the entire data map.
func (e *GenericEvent) SetData(data DataMap) {
	if data != nil {
		e.data = data
	}
}

// StopPropagation sets the event to no longer propagate
// to subsequent event listeners.
func (e *GenericEvent) StopPropagation(abort bool) {
	e.propagationStopped = abort
}

// IsPropagationStopped returns whether the event is set
// to no longer propagate. In other words, this is
// whether the event dispatcher should stop handling
// this event and skip passing it to any subsequent
// event listeners.
func (e *GenericEvent) IsPropagationStopped() bool {
	return e.propagationStopped
}

// Interface guards
var (
	_ Event = (*GenericEvent)(nil)
)
