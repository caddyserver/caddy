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
	"encoding/json"
	"fmt"
	"sort"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(EventApp{})
}

// EventApp is a global event system.
type EventApp struct {
	// Registers each of these event subscribers
	SubscribersRaw []json.RawMessage `json:"subscribers,omitempty" caddy:"namespace=event.subscribers inline_key=subscriber"`

	listeners map[caddy.ModuleID]map[Priority][]ListenerFunc
	optimized map[caddy.ModuleID][]ListenerFunc
	ready     bool
	logger    *zap.Logger
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
	app.listeners = make(map[caddy.ModuleID]map[Priority][]ListenerFunc)
	app.logger = ctx.Logger(app)

	// register all the configured subscribers
	if app.SubscribersRaw != nil {
		subscribersIface, err := ctx.LoadModule(app, "SubscribersRaw")
		if err != nil {
			return fmt.Errorf("loading event subscriber modules: %v", err)
		}
		for _, subscriber := range subscribersIface.([]Subscriber) {
			app.RegisterSubscriber(subscriber)
		}
	}

	return nil
}

// Validate ensures the app's configuration is valid.
func (app *EventApp) Validate() error {
	return nil
}

// Start runs the app.
func (app *EventApp) Start() error {
	// optimize the event listeners to order them by priority.
	app.optimizeListeners()

	// stop new listeners from being added,
	// and allow events to be dispatched.
	app.ready = true

	return nil
}

// Stop gracefully shuts down the app.
func (app *EventApp) Stop() error {
	return nil
}

// RegisterSubscriber registers all the listeners from a subscriber.
// Modules may register themselves as subscribers during their Provision
// phase. Subscribers cannot be registered after the config is running.
func (app *EventApp) RegisterSubscriber(subscriber Subscriber) {
	for eventID, entry := range subscriber.SubscribedEvents() {
		app.RegisterListener(eventID, entry)
	}
}

// RegisterListener registers a single event listener.
// Modules may register listeners during their Provision phase.
// Listeners cannot be registered after the config is running.
func (app *EventApp) RegisterListener(eventID caddy.ModuleID, entry ListenerEntry) {
	// if the app is already running, we don't allow adding new listeners.
	if app.ready {
		// TODO: Panic or something?
		return
	}

	if app.listeners[eventID] == nil {
		app.listeners[eventID] = make(map[Priority][]ListenerFunc)
	}

	// There may be more than one listener with the same priority,
	// for the same event, so we have an array of listeners for
	// each priority level. Listeners at the same priority level
	// will be in the order they are registered, which will not
	// have a guaranteed order because Caddy modules may be loaded
	// in an arbitrary order.
	app.listeners[eventID][entry.Priority] = append(
		app.listeners[eventID][entry.Priority],
		entry.Listener,
	)

	app.logger.Debug("registered listener",
		zap.String("event", eventID.Name()),
		zap.Int("priority", int(entry.Priority)),
	)
}

// Dispatch passes the event through the configured listeners synchronously.
func (app *EventApp) Dispatch(event Event) error {
	// if the app is not running, we don't allow dispatching events.
	if !app.ready {
		return fmt.Errorf("Cannot dispatch events until after the app is running")
	}

	// find the listeners for this event
	listeners, ok := app.optimized[event.ID()]
	if !ok {
		return nil
	}

	app.logger.Debug("dispatching", zap.String("event", event.ID().Name()))

	for _, listener := range listeners {
		// listeners may mark the event to stop subsequent
		// listeners from running on this event.
		if event.IsPropagationStopped() {
			app.logger.Debug("propogation stopped", zap.String("event", event.ID().Name()))
			break
		}

		// run the listener.
		err := listener(event)
		if err != nil {
			app.logger.Error("listener error",
				zap.String("event", event.ID().Name()),
				zap.Error(err),
			)
			return err
		}
	}

	return nil
}

// AsyncDispatch passes the event through the configured listeners asynchronously.
func (app *EventApp) AsyncDispatch(event Event) {
	go func(event Event) {
		_ = app.Dispatch(event)
	}(event)
}

// optimizeListeners orders the listeners by priority.
func (app *EventApp) optimizeListeners() {
	app.optimized = make(map[caddy.ModuleID][]ListenerFunc)
	for eventID, priorities := range app.listeners {
		app.optimized[eventID] = []ListenerFunc{}

		// sort the priorities (highest priority value first)
		keys := make([]int, 0)
		for k := range priorities {
			keys = append(keys, int(k))
		}
		sort.Sort(sort.Reverse(sort.IntSlice(keys)))

		// add all the listeners in order of priority
		for _, k := range keys {
			for _, listener := range priorities[Priority(k)] {
				app.optimized[eventID] = append(app.optimized[eventID], listener)
			}
		}
	}

	// we no longer need this map once we're running
	app.listeners = nil
}

// Interface guards
var (
	_ caddy.App         = (*EventApp)(nil)
	_ caddy.Provisioner = (*EventApp)(nil)
	_ caddy.Validator   = (*EventApp)(nil)
)
