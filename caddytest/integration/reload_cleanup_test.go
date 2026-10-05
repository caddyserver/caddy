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

package integration

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// blockingHandler is a test-only HTTP handler module that holds each
// request open until released, logs before responding, and records
// when it is cleaned up.
type blockingHandler struct {
	logger *zap.Logger
}

// blockingState is what blockingHandler reports to; each test run sets
// a fresh one before loading a config that uses the handler.
type blockingState struct {
	started  chan struct{}
	release  chan struct{}
	inFlight atomic.Bool
	cleanup  chan bool // true if a request was in flight
	log      *reloadLogWriter
}

var blocking atomic.Pointer[blockingState]

func (*blockingHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.blocking_test",
		New: func() caddy.Module { return new(blockingHandler) },
	}
}

func (h *blockingHandler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()
	return nil
}

func (h *blockingHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request, _ caddyhttp.Handler) error {
	b := blocking.Load()
	b.inFlight.Store(true)
	defer b.inFlight.Store(false)
	b.started <- struct{}{}
	<-b.release
	h.logger.Info("finishing request")
	_, err := io.WriteString(w, "done")
	return err
}

func (*blockingHandler) Cleanup() error {
	b := blocking.Load()
	b.cleanup <- b.inFlight.Load()
	return nil
}

// reloadLogWriter is a log writer that remembers whether anything
// was written to it after it was closed.
type reloadLogWriter struct {
	mu              sync.Mutex
	lines           int
	closed          bool
	writeAfterClose bool
}

func (w *reloadLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		w.writeAfterClose = true
		return 0, os.ErrClosed
	}
	w.lines++
	return len(p), nil
}

func (w *reloadLogWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
	return nil
}

func (w *reloadLogWriter) state() (lines int, closed, writeAfterClose bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.lines, w.closed, w.writeAfterClose
}

// reloadLogOutput is a test-only log writer module which opens the
// current blockingState's log writer.
type reloadLogOutput struct{}

func (reloadLogOutput) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.logging.writers.reload_test",
		New: func() caddy.Module { return new(reloadLogOutput) },
	}
}

func (reloadLogOutput) String() string    { return "reload_test" }
func (reloadLogOutput) WriterKey() string { return "reload_test" }

func (reloadLogOutput) OpenWriter() (io.WriteCloser, error) {
	return blocking.Load().log, nil
}

func init() {
	caddy.RegisterModule(new(blockingHandler))
	caddy.RegisterModule(reloadLogOutput{})
}

// TestReloadCleanupWaitsForActiveRequest checks that on a config reload,
// the old config's handlers and resources, such as a log writer only the
// old config has, are not cleaned up while they are still serving a
// request, but are once that request ends.
func TestReloadCleanupWaitsForActiveRequest(t *testing.T) {
	const oldLogging = `"logging": {"logs": {"reload_test": {
		"writer": {"output": "reload_test"},
		"include": ["http.handlers.blocking_test"]
	}}},`
	const config = `{
		"admin": {"disabled": true},
		%s
		"apps": {"http": {
			"grace_period": "10s",
			"servers": {"srv0": {
				"listen": [":9080"],
				"routes": [{"handle": [{"handler": %q}]}]
			}}
		}}
	}`
	b := &blockingState{
		started: make(chan struct{}, 1),
		release: make(chan struct{}),
		cleanup: make(chan bool, 1),
		log:     new(reloadLogWriter),
	}
	blocking.Store(b)
	if err := caddy.Load(fmt.Appendf(nil, config, oldLogging, "blocking_test"), true); err != nil {
		t.Fatalf("loading config: %v", err)
	}
	t.Cleanup(func() { _ = caddy.Stop() })

	type result struct {
		body string
		err  error
	}
	requestDone := make(chan result, 1)
	go func() {
		resp, err := http.Get("http://localhost:9080/")
		if err != nil {
			requestDone <- result{err: err}
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		requestDone <- result{string(body), err}
	}()
	select {
	case <-b.started:
	case <-time.After(5 * time.Second):
		t.Fatal("request never reached the handler")
	}

	// reload with a config that no longer has the blocking handler or its log
	if err := caddy.Load(fmt.Appendf(nil, config, "", "static_response"), true); err != nil {
		t.Fatalf("reloading config: %v", err)
	}

	select {
	case <-b.cleanup:
		t.Fatal("handler was cleaned up while it was still serving a request")
	case <-time.After(100 * time.Millisecond):
	}
	if _, closed, _ := b.log.state(); closed {
		t.Fatal("old log writer was closed while a request was still being served")
	}

	close(b.release)

	select {
	case r := <-requestDone:
		if r.err != nil {
			t.Fatalf("request failed: %v", r.err)
		}
		if r.body != "done" {
			t.Fatalf("unexpected response body: %q", r.body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("request did not complete after being released")
	}
	if lines, _, writeAfterClose := b.log.state(); writeAfterClose || lines == 0 {
		t.Fatalf("draining request could not log to the old log writer (lines=%d, write after close=%t)", lines, writeAfterClose)
	}

	select {
	case inFlight := <-b.cleanup:
		if inFlight {
			t.Error("handler was cleaned up while it was still serving a request")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler was not cleaned up after the request ended")
	}
	if _, closed, _ := b.log.state(); !closed {
		t.Error("old log writer was not closed after the request ended")
	}
}
