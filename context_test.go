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
	"io"
	"sync"
	"sync/atomic"
	"testing"
)

func TestContextCancellationCallbacks(t *testing.T) {
	ctx, cancel := NewContextWithCause(Context{Context: context.Background()})
	copy := ctx
	derived := ctx.WithValue("key", "value")
	var count atomic.Int32
	for _, c := range []*Context{&ctx, &copy, &derived} {
		c.OnCancel(func() { count.Add(1) })
	}
	cause := errors.New("test cancellation")
	cancel(cause)
	cancel(errors.New("second cancellation"))
	copy.OnCancel(func() { count.Add(1) })
	if got := count.Load(); got != 4 {
		t.Fatalf("callbacks ran %d times, want 4", got)
	}
	if context.Cause(ctx) != cause {
		t.Fatalf("cancellation cause = %v, want %v", context.Cause(ctx), cause)
	}
}

func TestContextCancellationLifetimes(t *testing.T) {
	parent, cancelParent := NewContext(Context{Context: context.Background()})
	child, cancelChild := NewContext(parent)
	var parents, children int
	parent.OnCancel(func() { parents++ })
	child.OnCancel(func() { children++ })
	cancelChild()
	if parents != 0 || children != 1 {
		t.Fatalf("after child cancel: parent=%d child=%d", parents, children)
	}
	cancelParent()
	cancelChild()
	if parents != 1 || children != 1 {
		t.Fatalf("cleanup counts: parent=%d child=%d", parents, children)
	}
}

func TestContextOnCancelZeroValue(t *testing.T) {
	var ctx Context
	ctx.OnCancel(func() { t.Fatal("callback on context without cancel func must not run") })
}

func TestContextCancellationConcurrent(t *testing.T) {
	ctx, cancel := NewContext(Context{Context: context.Background()})
	cleaner := new(contextTestCleaner)
	ctx.moduleInstances["test"] = []Module{cleaner}
	var count atomic.Int32
	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			copy := ctx
			copy.OnCancel(func() { count.Add(1) })
			cancel()
		})
	}
	wg.Wait()
	if count.Load() != 50 {
		t.Fatalf("callbacks ran %d times, want 50", count.Load())
	}
	if cleaner.count.Load() != 1 {
		t.Fatalf("module cleanup ran %d times, want 1", cleaner.count.Load())
	}
}

type contextTestCleaner struct{ count atomic.Int32 }

func (*contextTestCleaner) CaddyModule() ModuleInfo { return ModuleInfo{ID: "test"} }
func (c *contextTestCleaner) Cleanup() error {
	c.count.Add(1)
	return nil
}

func TestContextWithValuePreservesMetricsRegistry(t *testing.T) {
	ctx, cancel := NewContext(Context{Context: context.Background()})
	t.Cleanup(cancel)

	reg := ctx.GetMetricsRegistry()
	if reg == nil {
		t.Fatal("expected a metrics registry on the base context")
	}

	type testKey struct{}
	derived := ctx.WithValue(testKey{}, "value")
	if got := derived.GetMetricsRegistry(); got != reg {
		t.Fatalf("WithValue must preserve the metrics registry: got %p, want %p", got, reg)
	}
}

func ExampleContext_LoadModule() {
	// this whole first part is just setting up for the example;
	// note the struct tags - very important; we specify inline_key
	// because that is the only way to know the module name
	var ctx Context
	myStruct := &struct {
		// This godoc comment will appear in module documentation.
		GuestModuleRaw json.RawMessage `json:"guest_module,omitempty" caddy:"namespace=example inline_key=name"`

		// this is where the decoded module will be stored; in this
		// example, we pretend we need an io.Writer but it can be
		// any interface type that is useful to you
		guestModule io.Writer
	}{
		GuestModuleRaw: json.RawMessage(`{"name":"module_name","foo":"bar"}`),
	}

	// if a guest module is provided, we can load it easily
	if myStruct.GuestModuleRaw != nil {
		mod, err := ctx.LoadModule(myStruct, "GuestModuleRaw")
		if err != nil {
			// you'd want to actually handle the error here
			// return fmt.Errorf("loading guest module: %v", err)
		}
		// mod contains the loaded and provisioned module,
		// it is now ready for us to use
		myStruct.guestModule = mod.(io.Writer)
	}

	// use myStruct.guestModule from now on
}

func ExampleContext_LoadModule_array() {
	// this whole first part is just setting up for the example;
	// note the struct tags - very important; we specify inline_key
	// because that is the only way to know the module name
	var ctx Context
	myStruct := &struct {
		// This godoc comment will appear in module documentation.
		GuestModulesRaw []json.RawMessage `json:"guest_modules,omitempty" caddy:"namespace=example inline_key=name"`

		// this is where the decoded module will be stored; in this
		// example, we pretend we need an io.Writer but it can be
		// any interface type that is useful to you
		guestModules []io.Writer
	}{
		GuestModulesRaw: []json.RawMessage{
			json.RawMessage(`{"name":"module1_name","foo":"bar1"}`),
			json.RawMessage(`{"name":"module2_name","foo":"bar2"}`),
		},
	}

	// since our input is []json.RawMessage, the output will be []any
	mods, err := ctx.LoadModule(myStruct, "GuestModulesRaw")
	if err != nil {
		// you'd want to actually handle the error here
		// return fmt.Errorf("loading guest modules: %v", err)
	}
	for _, mod := range mods.([]any) {
		myStruct.guestModules = append(myStruct.guestModules, mod.(io.Writer))
	}

	// use myStruct.guestModules from now on
}

func ExampleContext_LoadModule_map() {
	// this whole first part is just setting up for the example;
	// note the struct tags - very important; we don't specify
	// inline_key because the map key is the module name
	var ctx Context
	myStruct := &struct {
		// This godoc comment will appear in module documentation.
		GuestModulesRaw ModuleMap `json:"guest_modules,omitempty" caddy:"namespace=example"`

		// this is where the decoded module will be stored; in this
		// example, we pretend we need an io.Writer but it can be
		// any interface type that is useful to you
		guestModules map[string]io.Writer
	}{
		GuestModulesRaw: ModuleMap{
			"module1_name": json.RawMessage(`{"foo":"bar1"}`),
			"module2_name": json.RawMessage(`{"foo":"bar2"}`),
		},
	}

	// since our input is map[string]json.RawMessage, the output will be map[string]any
	mods, err := ctx.LoadModule(myStruct, "GuestModulesRaw")
	if err != nil {
		// you'd want to actually handle the error here
		// return fmt.Errorf("loading guest modules: %v", err)
	}
	for modName, mod := range mods.(map[string]any) {
		myStruct.guestModules[modName] = mod.(io.Writer)
	}

	// use myStruct.guestModules from now on
}
