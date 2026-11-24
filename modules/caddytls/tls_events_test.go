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

package caddytls

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyevents"
)

type testEventHandler struct {
	called atomic.Int32
	origin atomic.Value
}

func (h *testEventHandler) Handle(_ context.Context, e caddy.Event) error {
	h.called.Add(1)
	if orig := e.Origin(); orig != nil {
		h.origin.Store(orig.CaddyModule().String())
	}
	return nil
}

var reloadTestHandler = new(testEventHandler)

type reloadTestEventHandlerModule struct{}

func init() {
	caddy.RegisterModule(reloadTestEventHandlerModule{})
}

func (reloadTestEventHandlerModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "events.handlers.test_reload",
		New: func() caddy.Module { return new(reloadTestEventHandlerModule) },
	}
}

func (reloadTestEventHandlerModule) Handle(ctx context.Context, e caddy.Event) error {
	return reloadTestHandler.Handle(ctx, e)
}

func TestOnEventSurvivesCanceledContext(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	eventsApp := new(caddyevents.App)
	if err := eventsApp.Provision(ctx); err != nil {
		t.Fatalf("provisioning events app: %v", err)
	}

	handler := new(testEventHandler)
	if err := eventsApp.Subscribe(&caddyevents.Subscription{
		Events:   []string{"cert_obtained"},
		Modules:  []caddy.ModuleID{"tls"},
		Handlers: []caddyevents.Handler{handler},
	}); err != nil {
		t.Fatalf("subscribing to cert_obtained: %v", err)
	}
	if err := eventsApp.Start(); err != nil {
		t.Fatalf("starting events app: %v", err)
	}

	// Create a TLS app with a canceled context (simulating an unloaded config after reload)
	// while retaining module ancestry via LoadModuleByID.
	tlsCtx, cancelTLS := caddy.NewContext(caddy.Context{Context: context.Background()})
	tlsAppVal, err := tlsCtx.LoadModuleByID("tls", json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("loading tls module: %v", err)
	}
	tlsApp := tlsAppVal.(*TLS)
	tlsApp.events = eventsApp
	cancelTLS() // cancel immediately to simulate reload

	// An ongoing renewal from CertMagic finishes and invokes onEvent with an active context.
	if err := tlsApp.onEvent(context.Background(), "cert_obtained", map[string]any{"identifier": "example.com"}); err != nil {
		t.Fatalf("onEvent failed: %v", err)
	}

	if count := handler.called.Load(); count != 1 {
		t.Fatalf("expected handler to be called once, got %d", count)
	}
	if got, _ := handler.origin.Load().(string); got != "tls" {
		t.Fatalf("expected event origin %q, got %q", "tls", got)
	}
}

func TestShouldEmitSurvivesCanceledContext(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	eventsApp := new(caddyevents.App)
	if err := eventsApp.Provision(ctx); err != nil {
		t.Fatalf("provisioning events app: %v", err)
	}

	handler := new(testEventHandler)
	if err := eventsApp.On("cert_obtained", handler); err != nil {
		t.Fatalf("subscribing to cert_obtained: %v", err)
	}
	if err := eventsApp.Start(); err != nil {
		t.Fatalf("starting events app: %v", err)
	}

	tlsCtx, cancelTLS := caddy.NewContext(caddy.Context{Context: context.Background()})
	cancelTLS()

	tlsApp := &TLS{
		ctx:    tlsCtx,
		events: eventsApp,
	}

	if !tlsApp.shouldEmit("cert_obtained") {
		t.Fatal("expected shouldEmit to return true for subscribed event")
	}
}

func TestOnEventRoutesToActiveConfigAfterReload(t *testing.T) {
	reloadTestHandler.called.Store(0)
	reloadTestHandler.origin.Store("")

	initialCfg := []byte(`{
		"admin": {"disabled": true},
		"apps": {
			"events": {},
			"tls": {}
		}
	}`)
	if err := caddy.Load(initialCfg, true); err != nil {
		t.Fatalf("initial caddy.Load failed: %v", err)
	}
	t.Cleanup(func() {
		_ = caddy.Stop()
	})

	oldTLSVal, err := caddy.ActiveContext().AppIfConfigured("tls")
	if err != nil {
		t.Fatalf("getting initial tls app: %v", err)
	}
	oldTLS := oldTLSVal.(*TLS)

	// Reload Caddy with an active event subscription; oldTLS.ctx will be canceled.
	reloadedCfg := []byte(`{
		"admin": {"disabled": true},
		"apps": {
			"events": {
				"subscriptions": [{
					"events": ["cert_obtained"],
					"modules": ["tls"],
					"handlers": [{"handler": "test_reload"}]
				}]
			},
			"tls": {}
		}
	}`)
	if err := caddy.Load(reloadedCfg, true); err != nil {
		t.Fatalf("reload caddy.Load failed: %v", err)
	}

	if !oldTLS.shouldEmit("cert_obtained") {
		t.Fatal("expected oldTLS.shouldEmit to observe active events subscription after reload")
	}
	if err := oldTLS.onEvent(context.Background(), "cert_obtained", map[string]any{"identifier": "example.com"}); err != nil {
		t.Fatalf("oldTLS.onEvent failed after reload: %v", err)
	}

	if count := reloadTestHandler.called.Load(); count != 1 {
		t.Fatalf("expected active events handler to be called once after reload, got %d", count)
	}
	if got, _ := reloadTestHandler.origin.Load().(string); got != "tls" {
		t.Fatalf("expected event origin %q after reload, got %q", "tls", got)
	}
}
