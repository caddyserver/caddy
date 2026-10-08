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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/internal"
)

type cleanupTestModule struct {
	Key     string `json:"key"`
	control *cleanupTestControl
}

type cleanupTestControl struct {
	entered   chan struct{}
	proceed   chan struct{}
	cleaned   atomic.Int32
	fail      string
	onCleanup func()
}

var (
	cleanupTestControls sync.Map
	cleanupTestSequence atomic.Uint64
)

func init() {
	RegisterModule(cleanupTestModule{})
	// This intentionally incomplete registration exercises a loader error
	// otherwise prevented by RegisterModule's validation.
	modulesMu.Lock()
	modules["test.cleanup_no_constructor"] = ModuleInfo{ID: "test.cleanup_no_constructor"}
	modulesMu.Unlock()
}

func (cleanupTestModule) CaddyModule() ModuleInfo {
	return ModuleInfo{ID: "test.cleanup_hold", New: func() Module { return new(cleanupTestModule) }}
}

func (m *cleanupTestModule) Provision(Context) error {
	value, _ := cleanupTestControls.Load(m.Key)
	m.control = value.(*cleanupTestControl)
	if m.control.entered != nil {
		close(m.control.entered)
		<-m.control.proceed
	}
	if m.control.fail == "provision" {
		return errors.New("provision failed")
	}
	return nil
}

func (m *cleanupTestModule) Validate() error {
	if m.control.fail == "validate" {
		return errors.New("validate failed")
	}
	return nil
}

func (m *cleanupTestModule) Cleanup() error {
	m.control.cleaned.Add(1)
	if m.control.onCleanup != nil {
		m.control.onCleanup()
	}
	return nil
}

func cleanupTestConfig(t *testing.T, control *cleanupTestControl) json.RawMessage {
	t.Helper()
	key := fmt.Sprint(cleanupTestSequence.Add(1))
	cleanupTestControls.Store(key, control)
	t.Cleanup(func() { cleanupTestControls.Delete(key) })
	return json.RawMessage(fmt.Sprintf(`{"key":%q}`, key))
}

func cleanupTestContext(t *testing.T) (Context, context.CancelCauseFunc, *cleanupTestControl) {
	t.Helper()
	ctx, cancel := NewContextWithCause(Context{Context: context.Background()})
	control := new(cleanupTestControl)
	if _, err := ctx.LoadModuleByID("test.cleanup_hold", cleanupTestConfig(t, control)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(nil) })
	return ctx, cancel, control
}

func TestContextCleanupHolds(t *testing.T) {
	ctx, cancel, control := cleanupTestContext(t)
	copyCtx := ctx
	type key struct{}
	valued := ctx.WithValue(key{}, 42)
	release1, release2 := copyCtx.HoldCleanup(), valued.HoldCleanup()
	cause := errors.New("retired")
	cancel(cause)
	cancel(errors.New("later"))
	if ctx.Err() != context.Canceled || context.Cause(valued) != cause {
		t.Fatal("cancellation or first cause was delayed/changed")
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("Done was delayed")
	}
	if valued.Value(key{}) != 42 {
		t.Fatal("WithValue lost value")
	}
	release1()
	release1()
	if control.cleaned.Load() != 0 {
		t.Fatal("cleanup ran with a remaining hold")
	}
	release2()
	release2()
	if control.cleaned.Load() != 1 {
		t.Fatal("cleanup did not run exactly once")
	}
}

func TestContextCleanupLateHoldAndNoHold(t *testing.T) {
	ctx, cancel, control := cleanupTestContext(t)
	cancel(nil)
	if control.cleaned.Load() != 1 {
		t.Fatal("unheld cleanup must remain synchronous")
	}
	ctx.HoldCleanup()()
	cancel(nil)
	if control.cleaned.Load() != 1 {
		t.Fatal("late acquisition or cancellation repeated cleanup")
	}
	if _, err := ctx.LoadModuleByID("test.cleanup_hold", nil); err == nil {
		t.Fatal("load succeeded after cancellation")
	}
}

func TestContextCleanupConcurrentCancelRelease(t *testing.T) {
	ctx, cancel, control := cleanupTestContext(t)
	releases := make([]func(), 32)
	for i := range releases {
		releases[i] = ctx.HoldCleanup()
	}
	var wg sync.WaitGroup
	for _, release := range releases {
		wg.Go(func() { cancel(nil); release(); release() })
	}
	wg.Wait()
	if control.cleaned.Load() != 1 {
		t.Fatal("concurrent cancellation/release repeated cleanup")
	}
}

func TestContextCleanupParentCancellation(t *testing.T) {
	parent, cancelParent := context.WithCancelCause(context.Background())
	ctx, cancel := NewContextWithCause(Context{Context: parent})
	control := new(cleanupTestControl)
	if _, err := ctx.LoadModuleByID("test.cleanup_hold", cleanupTestConfig(t, control)); err != nil {
		t.Fatal(err)
	}
	release := ctx.HoldCleanup()
	cause := errors.New("parent")
	cancelParent(cause)
	release()
	if context.Cause(ctx) != cause || control.cleaned.Load() != 0 {
		t.Fatal("parent cancellation must not retire child lifecycle")
	}
	ctx.HoldCleanup()() // canceled but not retired: still a no-op
	if err := internal.WaitForCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	cancel(errors.New("child"))
	if control.cleaned.Load() != 1 || context.Cause(ctx) != cause {
		t.Fatal("explicit cancellation failed to clean or changed parent cause")
	}
}

func TestContextCleanupCapturedParentCallbacks(t *testing.T) {
	parent := Context{Context: context.Background()}
	var child Context
	control := new(cleanupTestControl)
	called := 0
	parent.OnCancel(func() {
		called++
		if child.Err() == nil {
			t.Error("callback preceded cancellation")
		}
		if control.cleaned.Load() != 0 {
			t.Error("callback ran after module cleanup")
		}
	})
	ctx, cancel := NewContext(parent)
	cancel = sync.OnceFunc(cancel)
	child = ctx
	if _, err := child.LoadModuleByID("test.cleanup_hold", cleanupTestConfig(t, control)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cancel)
	parent.OnCancel(func() { t.Error("callback appended after construction was captured") })
	ctx.OnCancel(func() { t.Error("child callback unexpectedly ran on its own cancellation") })
	cancel()
	if called != 1 {
		t.Fatal("captured parent callback was deferred")
	}
	if control.cleaned.Load() != 1 {
		t.Fatal("unheld module cleanup did not follow callback")
	}
}

func TestContextCleanupInFlightLoad(t *testing.T) {
	for _, failure := range []string{"", "provision", "validate"} {
		t.Run(failure, func(t *testing.T) {
			ctx, cancel, existing := cleanupTestContext(t)
			loading := &cleanupTestControl{entered: make(chan struct{}), proceed: make(chan struct{}), fail: failure}
			raw := cleanupTestConfig(t, loading)
			result := make(chan error, 1)
			finished := make(chan struct{})
			var proceedOnce sync.Once
			proceed := func() { proceedOnce.Do(func() { close(loading.proceed) }) }
			defer func() { proceed(); <-finished }()
			go func() { defer close(finished); _, err := ctx.LoadModuleByID("test.cleanup_hold", raw); result <- err }()
			<-loading.entered
			cancel(nil)
			if existing.cleaned.Load() != 0 {
				t.Fatal("cleanup ran during provisioning")
			}
			proceed()
			err := <-result
			if (err != nil) != (failure != "") {
				t.Fatalf("unexpected load result: %v", err)
			}
			if existing.cleaned.Load() != 1 || loading.cleaned.Load() != 1 {
				t.Fatal("loaded or failed module was not cleaned exactly once")
			}
		})
	}
}

func TestContextCleanupLoadErrorsReleaseHold(t *testing.T) {
	for _, tc := range []struct {
		id  string
		raw json.RawMessage
	}{
		{"test.cleanup_unknown", nil},
		{"test.cleanup_no_constructor", nil},
		{"test.cleanup_hold", json.RawMessage(`{"unknown":true}`)},
		{"test.cleanup_hold", json.RawMessage(`null`)},
	} {
		t.Run(tc.id+string(tc.raw), func(t *testing.T) {
			ctx, cancel, control := cleanupTestContext(t)
			if _, err := ctx.LoadModuleByID(tc.id, tc.raw); err == nil {
				t.Fatal("expected load error")
			}
			cancel(nil)
			if control.cleaned.Load() != 1 {
				t.Fatal("error path leaked internal hold")
			}
		})
	}
}

func TestContextCleanupRecursiveReleaseAndLoad(t *testing.T) {
	ctx, cancel, control := cleanupTestContext(t)
	release := ctx.HoldCleanup()
	control.onCleanup = func() {
		release()
		if _, err := ctx.LoadModuleByID("test.cleanup_hold", nil); err == nil {
			t.Error("recursive load succeeded")
		}
	}
	cancel(nil)
	finished := make(chan struct{})
	go func() { release(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("recursive cleanup deadlocked")
	}
}

func TestContextCleanupWaitDeadlineAndCompletion(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		t.Run(fmt.Sprint(blocked), func(t *testing.T) {
			ctx, cancel, control := cleanupTestContext(t)
			release := ctx.HoldCleanup()
			entered, proceed, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
			if blocked {
				control.onCleanup = func() { close(entered); <-proceed }
			}
			cancel(nil)
			if blocked {
				go func() { release(); close(finished) }()
				<-entered
			}
			deadline, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer stop()
			if err := internal.WaitForCleanup(deadline); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("wait failed to honor deadline: %v", err)
			}
			if blocked {
				close(proceed)
				<-finished
			} else {
				release()
			}
			if err := internal.WaitForCleanup(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type cleanupWaitTestContext struct {
	context.Context
	started chan struct{}
	once    sync.Once
}

func (ctx *cleanupWaitTestContext) Done() <-chan struct{} {
	ctx.once.Do(func() { close(ctx.started) })
	return ctx.Context.Done()
}

func TestContextCleanupWaitIncludesRetirementDuringCleanup(t *testing.T) {
	parent, cancelParent, parentControl := cleanupTestContext(t)
	child, cancelChild, _ := cleanupTestContext(t)
	releaseParent, releaseChild := parent.HoldCleanup(), child.HoldCleanup()
	defer releaseParent()
	defer releaseChild()
	parentControl.onCleanup = func() { cancelChild(nil) }
	cancelParent(nil)
	deadline, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer stop()
	waitCtx := &cleanupWaitTestContext{Context: deadline, started: make(chan struct{})}
	result := make(chan error, 1)
	go func() { result <- internal.WaitForCleanup(waitCtx) }()
	<-waitCtx.started // waiter has snapshotted the held parent lifecycle
	releaseParent()   // parent cleanup retires the still-held child
	if err := <-result; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wait omitted lifecycle retired during cleanup: %v", err)
	}
}

func TestContextCleanupConcurrentLoadCopies(t *testing.T) {
	ctx, cancel, existing := cleanupTestContext(t)
	type key struct{}
	valued := ctx.WithValue(key{}, true)
	copies := []Context{ctx, ctx, valued}
	const loads = 32
	proceed := make(chan struct{})
	var proceedOnce sync.Once
	resume := func() { proceedOnce.Do(func() { close(proceed) }) }
	var wg sync.WaitGroup
	defer func() { resume(); wg.Wait() }()
	controls := make([]*cleanupTestControl, loads)
	results := make(chan error, loads)
	for i := range controls {
		control := &cleanupTestControl{entered: make(chan struct{}), proceed: proceed}
		controls[i] = control
		raw := cleanupTestConfig(t, control)
		copyCtx := copies[i%len(copies)]
		wg.Go(func() {
			_, err := copyCtx.LoadModuleByID("test.cleanup_hold", raw)
			results <- err
		})
	}
	deadline, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	for _, control := range controls {
		select {
		case <-control.entered:
		case <-deadline.Done():
			t.Fatal("concurrent module loads did not enter provisioning")
		}
	}
	cancel(nil)
	if existing.cleaned.Load() != 0 {
		t.Fatal("cleanup ran while context copies were loading modules")
	}
	resume()
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Error(err)
		}
	}
	if existing.cleaned.Load() != 1 {
		t.Fatal("existing module was not cleaned exactly once")
	}
	for _, control := range controls {
		if control.cleaned.Load() != 1 {
			t.Fatal("concurrently registered module was not cleaned exactly once")
		}
	}
}
