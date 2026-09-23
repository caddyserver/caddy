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
	"io"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2"
)

// discardLogger stands in for a production logger: a real core at info level,
// so debug output is filtered but everything else behaves normally.
func discardLogger() *zap.Logger {
	return zap.New(zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		zapcore.AddSync(io.Discard),
		zapcore.InfoLevel,
	))
}

func testApp(tb testing.TB) (*App, caddy.Context, context.CancelFunc) {
	tb.Helper()
	app := &App{
		logger:        discardLogger(),
		subscriptions: make(map[string]map[caddy.ModuleID][]Handler),
	}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	return app, ctx, cancel
}

type countingHandler struct{ count int }

func (h *countingHandler) Handle(context.Context, caddy.Event) error {
	h.count++
	return nil
}

// Emit takes a shortcut when nothing is subscribed; a handler bound to the
// event by name must still be invoked.
func TestEmitDispatchesToNamedSubscriber(t *testing.T) {
	app, ctx, cancel := testApp(t)
	defer cancel()

	h := new(countingHandler)
	if err := app.On("cert_obtained", h); err != nil {
		t.Fatal(err)
	}

	app.Emit(ctx, "cert_obtained", nil)
	if h.count != 1 {
		t.Errorf("handler invoked %d times, want 1", h.count)
	}

	// an event nobody subscribed to must not reach it
	app.Emit(ctx, "cert_failed", nil)
	if h.count != 1 {
		t.Errorf("handler invoked %d times after unrelated event, want 1", h.count)
	}
}

// Subscribing without naming an event binds to every event, which is stored
// under the empty event name; the shortcut has to account for that.
func TestEmitDispatchesToCatchAllSubscriber(t *testing.T) {
	app, ctx, cancel := testApp(t)
	defer cancel()

	h := new(countingHandler)
	if err := app.Subscribe(&Subscription{Handlers: []Handler{h}}); err != nil {
		t.Fatal(err)
	}

	app.Emit(ctx, "tls_get_certificate", nil)
	if h.count != 1 {
		t.Errorf("handler invoked %d times, want 1", h.count)
	}
}

// Some events, such as tls_get_certificate, are emitted on every TLS
// handshake, whether or not anything is subscribed to them.
func BenchmarkEmitNoSubscribers(b *testing.B) {
	app, ctx, cancel := testApp(b)
	defer cancel()

	data := map[string]any{"client_hello": "example.com"}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		app.Emit(ctx, "tls_get_certificate", data)
	}
}

func BenchmarkEmitNoSubscribersParallel(b *testing.B) {
	app, ctx, cancel := testApp(b)
	defer cancel()

	data := map[string]any{"client_hello": "example.com"}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			app.Emit(ctx, "tls_get_certificate", data)
		}
	})
}

func BenchmarkEmitWithSubscriber(b *testing.B) {
	app, ctx, cancel := testApp(b)
	defer cancel()

	if err := app.On("tls_get_certificate", new(countingHandler)); err != nil {
		b.Fatal(err)
	}
	data := map[string]any{"client_hello": "example.com"}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		app.Emit(ctx, "tls_get_certificate", data)
	}
}
