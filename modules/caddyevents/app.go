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

package caddyevents

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(App{})
}

// App implements a global eventing system within Caddy.
// Modules can emit and subscribe to events, providing
// hooks into deep parts of the code base that aren't
// otherwise accessible. Events provide information about
// what and when things are happening, and this facility
// allows handlers to take action when events occur,
// add information to the event's metadata, and even
// control program flow in some cases.
//
// Events are propagated in a DOM-like fashion. An event
// emitted from module `a.b.c` (the "origin") will first
// invoke handlers listening to `a.b.c`, then `a.b`,
// then `a`, then those listening regardless of origin.
// If a handler returns the special error Aborted, then
// propagation immediately stops and the event is marked
// as aborted. Emitters may optionally choose to adjust
// program flow based on an abort.
//
// Modules can subscribe to events by origin and/or name.
// A handler is invoked only if it is subscribed to the
// event by name and origin. Subscriptions should be
// registered during the provisioning phase, before apps
// are started.
//
// Event handlers are fired synchronously as part of the
// regular flow of the program. This allows event handlers
// to control the flow of the program if the origin permits
// it and also allows handlers to convey new information
// back into the origin module before it continues.
// In essence, event handlers are similar to HTTP
// middleware handlers.
//
// Event bindings/subscribers are unordered; i.e.
// event handlers are invoked in an arbitrary order.
// Event handlers should not rely on the logic of other
// handlers to succeed.
//
// The entirety of this app module is EXPERIMENTAL and
// subject to change. Pay attention to release notes.
type App struct {
	// Subscriptions bind handlers to one or more events
	// either globally or scoped to specific modules or module
	// namespaces.
	Subscriptions []*Subscription `json:"subscriptions,omitempty"`

	// Map of event name to map of module ID/namespace to handlers
	subscriptions map[string]map[caddy.ModuleID][]Handler

	logger  *zap.Logger
	started bool
}

// Subscription represents binding of one or more handlers to
// one or more events.
type Subscription struct {
	// The name(s) of the event(s) to bind to. Default: all events.
	Events []string `json:"events,omitempty"`

	// The ID or namespace of the module(s) from which events
	// originate to listen to for events. Default: all modules.
	//
	// Events propagate up, so events emitted by module "a.b.c"
	// will also trigger the event for "a.b" and "a". Thus, to
	// receive all events from "a.b.c" and "a.b.d", for example,
	// one can subscribe to either "a.b" or all of "a" entirely.
	Modules []caddy.ModuleID `json:"modules,omitempty"`

	// The event handler modules. These implement the actual
	// behavior to invoke when an event occurs. At least one
	// handler is required.
	HandlersRaw []json.RawMessage `json:"handlers,omitempty" caddy:"namespace=events.handlers inline_key=handler"`

	// The decoded handlers; Go code that is subscribing to
	// an event should set this field directly; HandlersRaw
	// is meant for JSON configuration to fill out this field.
	Handlers []Handler `json:"-"`
}

// CaddyModule returns the Caddy module information.
func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "events",
		New: func() caddy.Module { return new(App) },
	}
}

// Provision sets up the app.
func (app *App) Provision(ctx caddy.Context) error {
	app.logger = ctx.Logger()
	app.subscriptions = make(map[string]map[caddy.ModuleID][]Handler)

	for _, sub := range app.Subscriptions {
		if sub.HandlersRaw == nil {
			continue
		}
		handlersIface, err := ctx.LoadModule(sub, "HandlersRaw")
		if err != nil {
			return fmt.Errorf("loading event subscriber modules: %v", err)
		}
		for _, h := range handlersIface.([]any) {
			sub.Handlers = append(sub.Handlers, h.(Handler))
		}
		if len(sub.Handlers) == 0 {
			// pointless to bind without any handlers
			return fmt.Errorf("no handlers defined")
		}
	}

	return nil
}

// Start runs the app.
func (app *App) Start() error {
	for _, sub := range app.Subscriptions {
		if err := app.Subscribe(sub); err != nil {
			return err
		}
	}

	app.started = true

	return nil
}

// Stop gracefully shuts down the app.
func (app *App) Stop() error {
	return nil
}

// Subscribe binds one or more event handlers to one or more events
// according to the subscription s. For now, subscriptions can only
// be created during the provision phase; new bindings cannot be
// created after the events app has started.
func (app *App) Subscribe(s *Subscription) error {
	if app.started {
		return fmt.Errorf("events already started; new subscriptions closed")
	}

	// handle special case of catch-alls (omission of event name or module space implies all)
	if len(s.Events) == 0 {
		s.Events = []string{""}
	}
	if len(s.Modules) == 0 {
		s.Modules = []caddy.ModuleID{""}
	}

	for _, eventName := range s.Events {
		if app.subscriptions[eventName] == nil {
			app.subscriptions[eventName] = make(map[caddy.ModuleID][]Handler)
		}
		for _, originModule := range s.Modules {
			app.subscriptions[eventName][originModule] = append(app.subscriptions[eventName][originModule], s.Handlers...)
		}
	}

	return nil
}

// On is syntactic sugar for Subscribe() that binds a single handler
// to a single event from any module. If the eventName is empty string,
// it counts for all events.
func (app *App) On(eventName string, handler Handler) error {
	return app.Subscribe(&Subscription{
		Events:   []string{eventName},
		Handlers: []Handler{handler},
	})
}

// Emit creates and dispatches an event named eventName to all relevant handlers with
// the metadata data. Events are emitted and propagated synchronously. The returned Event
// value will have any additional information from the invoked handlers.
//
// Note that the data map is not copied, for efficiency. After Emit() is called, the
// data passed in should not be changed in other goroutines.
func (app *App) Emit(ctx caddy.Context, eventName string, data map[string]any) caddy.Event {
	logger := app.logger.With(zap.String("name", eventName))

	e, err := caddy.NewEvent(ctx, eventName, data)
	if err != nil {
		logger.Error("failed to create event", zap.Error(err))
	}

	var originModule caddy.ModuleInfo
	var originModuleID caddy.ModuleID
	var originModuleName string
	if origin := e.Origin(); origin != nil {
		originModule = origin.CaddyModule()
		originModuleID = originModule.ID
		originModuleName = originModule.String()
	}

	logger = logger.With(
		zap.String("id", e.ID().String()),
		zap.String("origin", originModuleName))

	// add event info to replacer, make sure it's in the context
	repl, ok := ctx.Context.Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if !ok {
		repl = caddy.NewReplacer()
		ctx.Context = context.WithValue(ctx.Context, caddy.ReplacerCtxKey, repl)
	}
	repl.Map(func(key string) (any, bool) {
		switch key {
		case "event":
			return e, true
		case "event.id":
			return e.ID(), true
		case "event.name":
			return e.Name(), true
		case "event.time":
			return e.Timestamp(), true
		case "event.time_unix":
			return e.Timestamp().UnixMilli(), true
		case "event.module":
			return originModuleID, true
		case "event.data":
			return e.Data, true
		}

		if strings.HasPrefix(key, "event.data.") {
			key = strings.TrimPrefix(key, "event.data.")
			if val, ok := e.Data[key]; ok {
				return val, true
			}
		}

		return nil, false
	})

	logger = logger.WithLazy(zap.Any("data", e.Data))

	logger.Debug("event")

	// invoke handlers bound to the event by name and also all events; this for loop
	// iterates twice at most: once for the event name, once for "" (all events)
	for {
		moduleID := originModuleID

		// implement propagation up the module tree (i.e. start with "a.b.c" then "a.b" then "a" then "")
		for {
			if app.subscriptions[eventName] == nil {
				break // shortcut if event not bound at all
			}

			for _, handler := range app.subscriptions[eventName][moduleID] {
				select {
				case <-ctx.Done():
					logger.Error("context canceled; event handling stopped")
					return e
				default:
				}

				// this log can be a useful sanity check to ensure your handlers are in fact being invoked
				// (see https://github.com/mholt/caddy-events-exec/issues/6)
				logger.Debug("invoking subscribed handler",
					zap.String("subscribed_to", eventName),
					zap.Any("handler", handler))

				if err := handler.Handle(ctx, e); err != nil {
					aborted := errors.Is(err, caddy.ErrEventAborted)

					logger.Error("handler error",
						zap.Error(err),
						zap.Bool("aborted", aborted))

					if aborted {
						e.Aborted = err
						return e
					}
				}
			}

			if moduleID == "" {
				break
			}
			lastDot := strings.LastIndex(string(moduleID), ".")
			if lastDot < 0 {
				moduleID = "" // include handlers bound to events regardless of module
			} else {
				moduleID = moduleID[:lastDot]
			}
		}

		// include handlers listening to all events
		if eventName == "" {
			break
		}
		eventName = ""
	}

	return e
}

// Handler is a type that can handle events.
type Handler interface {
	Handle(context.Context, caddy.Event) error
}

// Interface guards
var (
	_ caddy.App         = (*App)(nil)
	_ caddy.Provisioner = (*App)(nil)
)
