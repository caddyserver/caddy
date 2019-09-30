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
	"fmt"
	"log"
	"reflect"

	"github.com/mholt/certmagic"
)

// Context is a type which defines the lifetime of modules that
// are loaded and provides access to the parent configuration
// that spawned the modules which are loaded. It should be used
// with care and wrapped with derivation functions from the
// standard context package only if you don't need the Caddy
// specific features. These contexts are cancelled when the
// lifetime of the modules loaded from it are over.
//
// Use NewContext() to get a valid value (but most modules will
// not actually need to do this).
type Context struct {
	context.Context
	moduleInstances map[string][]interface{}
	cfg             *Config
	cleanupFuncs    []func()
}

// NewContext provides a new context derived from the given
// context ctx. Normally, you will not need to call this
// function unless you are loading modules which have a
// different lifespan than the ones for the context the
// module was provisioned with. Be sure to call the cancel
// func when the context is to be cleaned up so that
// modules which are loaded will be properly unloaded.
// See standard library context package's documentation.
func NewContext(ctx Context) (Context, context.CancelFunc) {
	newCtx := Context{moduleInstances: make(map[string][]interface{}), cfg: ctx.cfg}
	c, cancel := context.WithCancel(ctx.Context)
	wrappedCancel := func() {
		cancel()

		for _, f := range ctx.cleanupFuncs {
			f()
		}

		for modName, modInstances := range newCtx.moduleInstances {
			for _, inst := range modInstances {
				if cu, ok := inst.(CleanerUpper); ok {
					err := cu.Cleanup()
					if err != nil {
						log.Printf("[ERROR] %s (%p): cleanup: %v", modName, inst, err)
					}
				}
			}
		}
	}
	newCtx.Context = c
	return newCtx, wrappedCancel
}

// OnCancel executes f when ctx is cancelled.
func (ctx *Context) OnCancel(f func()) {
	ctx.cleanupFuncs = append(ctx.cleanupFuncs, f)
}

// LoadModule decodes rawMsg into a new instance of mod and
// returns the value. If mod.New() does not return a pointer
// value, it is converted to one so that it is unmarshaled
// into the underlying concrete type. If mod.New is nil, an
// error is returned. If the module implements Validator or
// Provisioner interfaces, those methods are invoked to
// ensure the module is fully configured and valid before
// being used.
func (ctx Context) LoadModule(name string, rawMsg json.RawMessage) (interface{}, error) {
	modulesMu.Lock()
	mod, ok := modules[name]
	modulesMu.Unlock()
	if !ok {
		return nil, fmt.Errorf("unknown module: %s", name)
	}

	if mod.New == nil {
		return nil, fmt.Errorf("module '%s' has no constructor", mod.Name)
	}

	val := mod.New().(interface{})

	// value must be a pointer for unmarshaling into concrete type, even if
	// the module's concrete type is a slice or map; New() *should* return
	// a pointer, otherwise unmarshaling errors or panics will occur
	if rv := reflect.ValueOf(val); rv.Kind() != reflect.Ptr {
		log.Printf("[WARNING] ModuleInfo.New() for module '%s' did not return a pointer,"+
			" so we are using reflection to make a pointer instead; please fix this by"+
			" using new(Type) or &Type notation in your module's New() function.", name)
		val = reflect.New(rv.Type()).Elem().Addr().Interface().(Module)
	}

	// fill in its config only if there is a config to fill in
	if len(rawMsg) > 0 {
		err := strictUnmarshalJSON(rawMsg, &val)
		if err != nil {
			return nil, fmt.Errorf("decoding module config: %s: %v", mod.Name, err)
		}
	}

	if val == nil {
		// returned module values are almost always type-asserted
		// before being used, so a nil value would panic; and there
		// is no good reason to explicitly declare null modules in
		// a config; it might be because the user is trying to
		// achieve a result they aren't expecting, which is a smell
		return nil, fmt.Errorf("module value cannot be null")
	}

	if prov, ok := val.(Provisioner); ok {
		err := prov.Provision(ctx)
		if err != nil {
			// incomplete provisioning could have left state
			// dangling, so make sure it gets cleaned up
			if cleanerUpper, ok := val.(CleanerUpper); ok {
				err2 := cleanerUpper.Cleanup()
				if err2 != nil {
					err = fmt.Errorf("%v; additionally, cleanup: %v", err, err2)
				}
			}
			return nil, fmt.Errorf("provision %s: %v", mod.Name, err)
		}
	}

	if validator, ok := val.(Validator); ok {
		err := validator.Validate()
		if err != nil {
			// since the module was already provisioned, make sure we clean up
			if cleanerUpper, ok := val.(CleanerUpper); ok {
				err2 := cleanerUpper.Cleanup()
				if err2 != nil {
					err = fmt.Errorf("%v; additionally, cleanup: %v", err, err2)
				}
			}
			return nil, fmt.Errorf("%s: invalid configuration: %v", mod.Name, err)
		}
	}

	ctx.moduleInstances[name] = append(ctx.moduleInstances[name], val)

	return val, nil
}

// LoadModuleInline loads a module from a JSON raw message which decodes
// to a map[string]interface{}, where one of the keys is moduleNameKey
// and the corresponding value is the module name as a string, which
// can be found in the given scope.
//
// This allows modules to be decoded into their concrete types and
// used when their names cannot be the unique key in a map, such as
// when there are multiple instances in the map or it appears in an
// array (where there are no custom keys). In other words, the key
// containing the module name is treated special/separate from all
// the other keys.
func (ctx Context) LoadModuleInline(moduleNameKey, moduleScope string, raw json.RawMessage) (interface{}, error) {
	moduleName, raw, err := getModuleNameInline(moduleNameKey, raw)
	if err != nil {
		return nil, err
	}

	val, err := ctx.LoadModule(moduleScope+"."+moduleName, raw)
	if err != nil {
		return nil, fmt.Errorf("loading module '%s': %v", moduleName, err)
	}

	return val, nil
}

// App returns the configured app named name. If no app with
// that name is currently configured, a new empty one will be
// instantiated. (The app module must still be registered.)
func (ctx Context) App(name string) (interface{}, error) {
	if app, ok := ctx.cfg.apps[name]; ok {
		return app, nil
	}
	modVal, err := ctx.LoadModule(name, nil)
	if err != nil {
		return nil, fmt.Errorf("instantiating new module %s: %v", name, err)
	}
	ctx.cfg.apps[name] = modVal.(App)
	return modVal, nil
}

// Storage returns the configured Caddy storage implementation.
func (ctx Context) Storage() certmagic.Storage {
	return ctx.cfg.storage
}
