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
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/internal"
)

type sinkTestWriter struct {
	mu     sync.Mutex
	buffer bytes.Buffer
	closed atomic.Int32
}

func (w *sinkTestWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed.Load() != 0 {
		return 0, io.ErrClosedPipe
	}
	return w.buffer.Write(p)
}

func (w *sinkTestWriter) Close() error { w.closed.Add(1); return nil }

func (w *sinkTestWriter) contains(message string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return strings.Contains(w.buffer.String(), message)
}

type sinkTestWriterModule struct {
	Key string `json:"key"`
}

var (
	sinkTestWriters sync.Map
	sinkTestApps    sync.Map
	sinkTestSeq     atomic.Uint64
)

func init() {
	RegisterModule(sinkTestWriterModule{})
	RegisterModule(sinkTestFailureApp{})
}

func (sinkTestWriterModule) CaddyModule() ModuleInfo {
	return ModuleInfo{ID: "caddy.logging.writers.sink_reload_test", New: func() Module { return new(sinkTestWriterModule) }}
}

func (m *sinkTestWriterModule) String() string    { return m.WriterKey() }
func (m *sinkTestWriterModule) WriterKey() string { return "sink-reload-test:" + m.Key }
func (m *sinkTestWriterModule) OpenWriter() (io.WriteCloser, error) {
	value, ok := sinkTestWriters.Load(m.Key)
	if !ok {
		return nil, errors.New("missing test writer")
	}
	return value.(*sinkTestWriter), nil
}

type sinkTestFailureControl struct {
	fail    string
	hold    bool
	release func()
}

type sinkTestFailureApp struct {
	Key     string `json:"key"`
	control *sinkTestFailureControl
}

func (sinkTestFailureApp) CaddyModule() ModuleInfo {
	return ModuleInfo{ID: "sink_reload_test", New: func() Module { return new(sinkTestFailureApp) }}
}

func (m *sinkTestFailureApp) Provision(ctx Context) error {
	value, _ := sinkTestApps.Load(m.Key)
	m.control = value.(*sinkTestFailureControl)
	if m.control.hold {
		m.control.release = ctx.HoldCleanup()
	}
	if m.control.fail == "provision" {
		return errors.New("test provision failure")
	}
	return nil
}

func (m *sinkTestFailureApp) Start() error {
	if m.control.fail == "start" {
		return errors.New("test start failure")
	}
	return nil
}

func (m *sinkTestFailureApp) Stop() error { return nil }

type sinkTestEnv struct {
	t        *testing.T
	baseline *sinkTestWriter
	releases []func()
}

func newSinkTestEnv(t *testing.T) *sinkTestEnv {
	t.Helper()
	if err := Stop(); err != nil {
		t.Fatal(err)
	}
	originalWriter, originalFlags, originalPrefix := log.Writer(), log.Flags(), log.Prefix()
	defaultLoggerMu.RLock()
	originalDefault := defaultLogger
	defaultLoggerMu.RUnlock()
	env := &sinkTestEnv{t: t, baseline: new(sinkTestWriter)}
	log.SetOutput(env.baseline)
	log.SetFlags(log.LstdFlags)
	log.SetPrefix("baseline: ")
	t.Cleanup(func() {
		if err := Stop(); err != nil {
			t.Error(err)
		}
		for _, release := range env.releases {
			release()
		}
		deadline, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := internal.WaitForCleanup(deadline); err != nil {
			t.Error(err)
		}
		log.SetOutput(originalWriter)
		log.SetFlags(originalFlags)
		log.SetPrefix(originalPrefix)
		defaultLoggerMu.Lock()
		defaultLogger = originalDefault
		defaultLoggerMu.Unlock()
	})
	return env
}

func (env *sinkTestEnv) writerConfig() (*sinkTestWriter, map[string]any) {
	env.t.Helper()
	key := fmt.Sprint(sinkTestSeq.Add(1))
	writer := new(sinkTestWriter)
	sinkTestWriters.Store(key, writer)
	env.t.Cleanup(func() { sinkTestWriters.Delete(key) })
	return writer, map[string]any{"output": "sink_reload_test", "key": key}
}

func (env *sinkTestEnv) config(writer map[string]any, failure *sinkTestFailureControl) []byte {
	env.t.Helper()
	config := map[string]any{"admin": map[string]any{"disabled": true, "config": map[string]any{"persist": false}}}
	if writer != nil {
		config["logging"] = map[string]any{"sink": map[string]any{"writer": writer}}
	}
	if failure != nil {
		key := fmt.Sprint(sinkTestSeq.Add(1))
		sinkTestApps.Store(key, failure)
		env.t.Cleanup(func() { sinkTestApps.Delete(key) })
		// The failed candidate's explicit hold must survive Load returning.
		env.releases = append(env.releases, func() {
			if failure.release != nil {
				failure.release()
			}
		})
		config["apps"] = map[string]any{"sink_reload_test": map[string]any{"key": key}}
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		env.t.Fatal(err)
	}
	return encoded
}

func (env *sinkTestEnv) load(writer map[string]any) {
	env.t.Helper()
	if err := Load(env.config(writer, nil), true); err != nil {
		env.t.Fatal(err)
	}
}

func (env *sinkTestEnv) hold() func() {
	ctx := ActiveContext()
	release := ctx.HoldCleanup()
	env.releases = append(env.releases, release)
	return release
}

func TestSinkSuccessfulReload(t *testing.T) {
	env := newSinkTestEnv(t)
	a, aConfig := env.writerConfig()
	b, bConfig := env.writerConfig()
	env.load(aConfig)
	log.Print("initial-sink")
	if !a.contains("initial-sink") {
		t.Fatal("default log setup displaced the initial sink")
	}
	release := env.hold()
	env.load(bConfig)
	log.Print("replacement-sink-before-old-cleanup")
	if !b.contains("replacement-sink-before-old-cleanup") {
		t.Fatal("default log setup displaced the replacement sink")
	}
	if a.closed.Load() != 0 {
		t.Fatal("old sink closed while held")
	}
	release()
	log.Print("new-sink-after-old-cleanup")
	if !b.contains("new-sink-after-old-cleanup") || a.closed.Load() != 1 || b.closed.Load() != 0 {
		t.Fatal("old cleanup displaced or closed the new sink")
	}
	if log.Flags() != 0 || log.Prefix() != "" {
		t.Fatal("sink logger annotations were not preserved")
	}
}

func TestSinkFailedReload(t *testing.T) {
	for _, initialSink := range []bool{false, true} {
		for _, candidateSink := range []bool{false, true} {
			for _, stage := range []string{"provision", "start"} {
				for _, held := range []bool{false, true} {
					t.Run(fmt.Sprintf("sink=%t/candidate=%t/%s/held=%t", initialSink, candidateSink, stage, held), func(t *testing.T) {
						env := newSinkTestEnv(t)
						target := env.baseline
						if initialSink {
							writer, config := env.writerConfig()
							target = writer
							env.load(config)
						} else {
							env.load(nil)
						}
						var failed *sinkTestWriter
						var candidate map[string]any
						if candidateSink {
							failed, candidate = env.writerConfig()
						}
						control := &sinkTestFailureControl{fail: stage, hold: held}
						if err := Load(env.config(candidate, control), true); err == nil {
							t.Fatal("candidate unexpectedly succeeded")
						}
						log.Print("after-failed-reload")
						if !target.contains("after-failed-reload") || (failed != nil && failed.contains("after-failed-reload")) {
							t.Fatal("failed reload did not restore prior sink immediately")
						}
						if held {
							if failed != nil && failed.closed.Load() != 0 {
								t.Fatal("failed candidate's held writer closed early")
							}
							control.release()
						}
						if failed != nil && failed.closed.Load() != 1 {
							t.Fatal("failed candidate's writer was not closed once")
						}
						log.Print("after-failed-candidate-cleanup")
						if !target.contains("after-failed-candidate-cleanup") {
							t.Fatal("deferred failed cleanup displaced the prior sink")
						}
					})
				}
			}
		}
	}
}

func TestSinkFailureDuringLogging(t *testing.T) {
	env := newSinkTestEnv(t)
	a, aConfig := env.writerConfig()
	env.load(aConfig)
	failed, writer := env.writerConfig()
	config := map[string]any{
		"admin": map[string]any{"disabled": true},
		"logging": map[string]any{
			"sink": map[string]any{"writer": writer},
			"logs": map[string]any{"default": map[string]any{"with_stacktrace": "invalid"}},
		},
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := Load(encoded, true); err == nil {
		t.Fatal("invalid logging configuration succeeded")
	}
	log.Print("after-logging-failure")
	if !a.contains("after-logging-failure") || failed.closed.Load() != 1 {
		t.Fatal("logging setup failure did not restore the prior sink")
	}
}

func TestSinkRemovalAndRetiredGenerations(t *testing.T) {
	for _, removeSink := range []bool{false, true} {
		t.Run(fmt.Sprint(removeSink), func(t *testing.T) {
			env := newSinkTestEnv(t)
			a, aConfig := env.writerConfig()
			b, bConfig := env.writerConfig()
			env.load(aConfig)
			releaseA := env.hold()
			env.load(bConfig)
			releaseB := env.hold()
			if removeSink {
				env.load(nil)
			} else if err := Stop(); err != nil {
				t.Fatal(err)
			} else {
				releaseB()
			}
			log.Print("baseline-with-retired-generations")
			if !env.baseline.contains("baseline-with-retired-generations") {
				t.Fatal("retired sink displaced the baseline")
			}
			releaseB()
			releaseA()
			log.Print("baseline-after-retired-cleanup")
			if !env.baseline.contains("baseline-after-retired-cleanup") || a.closed.Load() != 1 || b.closed.Load() != 1 {
				t.Fatal("retired cleanup changed baseline or leaked writers")
			}
			if log.Flags() != log.LstdFlags || log.Prefix() != "baseline: " {
				t.Fatal("baseline logger annotations were not restored")
			}
		})
	}
}

func TestSinkOutOfOrderCleanup(t *testing.T) {
	env := newSinkTestEnv(t)
	_, aConfig := env.writerConfig()
	_, bConfig := env.writerConfig()
	c, cConfig := env.writerConfig()
	env.load(aConfig)
	releaseA := env.hold()
	env.load(bConfig)
	releaseB := env.hold()
	env.load(cConfig)
	for i, release := range []func(){releaseB, releaseA} {
		release()
		marker := fmt.Sprintf("newest-sink-after-release-%d", i)
		log.Print(marker)
		if !c.contains(marker) || c.closed.Load() != 0 {
			t.Fatal("out-of-order cleanup displaced the newest sink")
		}
	}
}
