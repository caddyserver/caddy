package caddy2

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"reflect"

	"github.com/mholt/certmagic"
)

type Context struct {
	context.Context
	moduleInstances map[string][]interface{}
	cfg             *Config
}

func NewContext(ctx Context) (Context, context.CancelFunc) {
	newCtx := Context{moduleInstances: make(map[string][]interface{}), cfg: ctx.cfg}
	c, cancel := context.WithCancel(ctx.Context)
	wrappedCancel := func() {
		cancel()
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

	val, err := mod.New()
	if err != nil {
		return nil, fmt.Errorf("initializing module '%s': %v", mod.Name, err)
	}

	// value must be a pointer for unmarshaling into concrete type
	if rv := reflect.ValueOf(val); rv.Kind() != reflect.Ptr {
		val = reflect.New(rv.Type()).Elem().Addr().Interface()
	}

	// fill in its config only if there is a config to fill in
	if len(rawMsg) > 0 {
		err = json.Unmarshal(rawMsg, &val)
		if err != nil {
			return nil, fmt.Errorf("decoding module config: %s: %v", mod.Name, err)
		}
	}

	if prov, ok := val.(Provisioner); ok {
		err := prov.Provision(ctx)
		if err != nil {
			return nil, fmt.Errorf("provision %s: %v", mod.Name, err)
		}
	}

	if validator, ok := val.(Validator); ok {
		err := validator.Validate(ctx)
		if err != nil {
			if cleanerUpper, ok := val.(CleanerUpper); ok {
				err2 := cleanerUpper.Cleanup()
				if err2 != nil {
					err = fmt.Errorf("%v; additionally, cleanup: %v", err, err2)
				}
				return nil, fmt.Errorf("%s: invalid configuration: %v", mod.Name, err)
			}
		}
	}

	ctx.moduleInstances[name] = append(ctx.moduleInstances[name], val)

	return val, nil
}

func (ctx Context) LoadModuleInline(moduleNameKey, moduleScope string, raw json.RawMessage) (interface{}, error) {
	moduleName, err := getModuleNameInline(moduleNameKey, raw)
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
