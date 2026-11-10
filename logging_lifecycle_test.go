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

package caddy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"testing"
)

func TestLoggingSinkReloadLifecycle(t *testing.T) {
	baseline, originalDefault := prepareLoggingLifecycle(t)
	a, sinkA, _ := lifecycleLogging(t, true)
	cancelA := provisionLifecycleLogging(t, a)
	log.Print("first sink")
	if !strings.Contains(sinkA.contents(), "first sink") {
		t.Fatal("standard logger did not reach initial sink")
	}

	b, sinkB, _ := lifecycleLogging(t, true)
	cancelB := provisionLifecycleLogging(t, b)
	cancelA()
	log.Print("replacement sink")
	if !strings.Contains(sinkB.contents(), "replacement sink") || !sinkA.isClosed() {
		t.Fatal("old config cleanup undid the replacement sink or leaked its writer")
	}
	if strings.Contains(sinkA.contents(), "replacement sink") {
		t.Fatal("replacement log reached old sink")
	}

	c, _, _ := lifecycleLogging(t, false)
	cancelC := provisionLifecycleLogging(t, c)
	cancelB()
	log.Print("sink removed")
	if !strings.Contains(baseline.contents(), "baseline: sink removed") {
		t.Fatalf("removed sink did not restore original logger: %s", baseline.contents())
	}
	if strings.Contains(sinkB.contents(), "sink removed") || !sinkB.isClosed() {
		t.Fatal("removed sink received another log or leaked its writer")
	}

	d, sinkD, _ := lifecycleLogging(t, true)
	cancelD := provisionLifecycleLogging(t, d)
	cancelC()
	log.Print("sink reintroduced")
	if !strings.Contains(sinkD.contents(), "sink reintroduced") {
		t.Fatal("sinkless config cleanup undid newer sink")
	}
	cancelD()
	if log.Writer() != baseline || log.Prefix() != "baseline: " || log.Flags() != log.Lmsgprefix {
		t.Fatal("final cleanup did not restore original standard logger state")
	}
	if defaultLogger != originalDefault {
		t.Fatal("final cleanup did not restore original Caddy logger")
	}
}

func TestLoggingFailedProvisioningRestoresOwner(t *testing.T) {
	for _, sink := range []bool{false, true} {
		t.Run(fmt.Sprintf("active_sink=%t", sink), func(t *testing.T) {
			testLoggingFailedProvisioningRestoresOwner(t, sink)
		})
	}
}

func testLoggingFailedProvisioningRestoresOwner(t *testing.T, sink bool) {
	baseline, _ := prepareLoggingLifecycle(t)
	active, activeSink, activeDefault := lifecycleLogging(t, sink)
	activeWriter := activeSink
	if activeWriter == nil {
		activeWriter = baseline
	}
	provisionLifecycleLogging(t, active)
	originalDefault := defaultLogger
	for _, stage := range []string{"sink", "default", "custom", "storage"} {
		for _, sink := range []bool{false, true} {
			if stage == "sink" && !sink {
				continue
			}
			t.Run(stage+map[bool]string{false: "/without_sink", true: "/with_sink"}[sink], func(t *testing.T) {
				failed, failedSink, failedDefault := lifecycleLogging(t, sink)
				switch stage {
				case "sink":
					failed.Sink.Level = "invalid"
				case "default":
					failed.Logs[DefaultLoggerName].Level = "invalid"
				case "custom":
					failed.Logs["broken"] = &CustomLog{BaseLog: BaseLog{Level: "invalid"}}
				}
				var cancel context.CancelFunc
				if stage == "storage" {
					ctx, err := provisionContext(&Config{
						Logging:    failed,
						StorageRaw: json.RawMessage(`{"module":"nonexistent"}`),
					}, false)
					if err == nil {
						t.Fatal("expected storage provisioning failure")
					}
					cancel = func() { ctx.cfg.cancelFunc(nil) }
				} else {
					ctx, cancelContext := NewContext(Context{Context: context.Background()})
					cancel = cancelContext
					if err := failed.openLogs(ctx); err == nil {
						t.Fatal("expected logging provisioning failure")
					}
				}
				t.Cleanup(cancel)
				cancel()
				cancel()
				log.Print("after failed provisioning")
				Log().Info("Caddy logger after failed provisioning")
				if !strings.Contains(activeWriter.contents(), "after failed provisioning") {
					t.Fatal("failure did not restore active sink")
				}
				if defaultLogger != originalDefault || activeWriter.isClosed() || activeDefault.isClosed() {
					t.Fatal("failure replaced or closed active loggers")
				}
				if stage != "sink" && !failedDefault.isClosed() {
					t.Fatal("failed configuration's default writer leaked")
				}
				if sink && !failedSink.isClosed() {
					t.Fatal("failed configuration's sink writer leaked")
				}
			})
		}
	}
}

func prepareLoggingLifecycle(t *testing.T) (*lifecycleLogWriter, *defaultCustomLog) {
	t.Helper()
	originalWriter, originalFlags, originalPrefix := log.Writer(), log.Flags(), log.Prefix()
	defaultLoggerMu.Lock()
	originalDefault := defaultLogger
	originalOwners, originalBaseline := loggingOwners, loggingBaseline
	loggingOwners = nil
	defaultLoggerMu.Unlock()
	baseline := new(lifecycleLogWriter)
	log.SetOutput(baseline)
	log.SetPrefix("baseline: ")
	log.SetFlags(log.Lmsgprefix)
	t.Cleanup(func() {
		defaultLoggerMu.Lock()
		if len(loggingOwners) != 0 {
			t.Error("configuration logger ownership leaked")
		}
		loggingOwners, loggingBaseline = originalOwners, originalBaseline
		defaultLogger = originalDefault
		defaultLoggerMu.Unlock()
		log.SetOutput(originalWriter)
		log.SetFlags(originalFlags)
		log.SetPrefix(originalPrefix)
	})
	return baseline, originalDefault
}

func lifecycleLogging(t *testing.T, sink bool) (*Logging, *lifecycleLogWriter, *lifecycleLogWriter) {
	t.Helper()
	defaultWriter := new(lifecycleLogWriter)
	defaultWriter.key = fmt.Sprintf("%s/default/%p", t.Name(), defaultWriter)
	logging := &Logging{Logs: map[string]*CustomLog{
		DefaultLoggerName: {BaseLog: BaseLog{writerOpener: defaultWriter}},
	}}
	var sinkWriter *lifecycleLogWriter
	if sink {
		sinkWriter = new(lifecycleLogWriter)
		sinkWriter.key = fmt.Sprintf("%s/sink/%p", t.Name(), sinkWriter)
		logging.Sink = &SinkLog{BaseLog: BaseLog{writerOpener: sinkWriter}}
	}
	return logging, sinkWriter, defaultWriter
}

func provisionLifecycleLogging(t *testing.T, logging *Logging) context.CancelFunc {
	t.Helper()
	ctx, cancel := NewContext(Context{Context: context.Background()})
	t.Cleanup(cancel)
	if err := logging.openLogs(ctx); err != nil {
		t.Fatal(err)
	}
	return cancel
}

type lifecycleLogWriter struct {
	mu     sync.Mutex
	buffer bytes.Buffer
	key    string
	closed bool
}

func (w *lifecycleLogWriter) WriterKey() string                   { return w.key }
func (w *lifecycleLogWriter) String() string                      { return w.key }
func (w *lifecycleLogWriter) OpenWriter() (io.WriteCloser, error) { return w, nil }
func (w *lifecycleLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, errors.New("write to closed lifecycle log")
	}
	return w.buffer.Write(p)
}
func (w *lifecycleLogWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
	return nil
}
func (w *lifecycleLogWriter) contents() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buffer.String()
}
func (w *lifecycleLogWriter) isClosed() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.closed
}
