package caddy2

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
)

// Module represents a Caddy module.
type Module struct {
	// Name is the full name of the module. It
	// must be unique and properly namespaced.
	Name string

	// New returns a new, empty instance of
	// the module's type. The host module
	// which loads this module will likely
	// invoke methods on the returned value.
	// It must return a pointer; if not, it
	// is converted into one.
	New func() (interface{}, error)

	// OnLoad is invoked after all module
	// instances ave been loaded. It receives
	// pointers to each instance of this
	// module, and any state from a previous
	// running configuration, which may be
	// nil.
	//
	// If this module is to carry "global"
	// state between all instances through
	// reloads, you might find it helpful
	// to return it.
	// TODO: Is this really better/safer than a global variable?
	OnLoad func(instances []interface{}, priorState interface{}) (newState interface{}, err error)

	// OnUnload is called after all module
	// instances have been stopped, possibly
	// in favor of a new configuration. It
	// receives the state given by OnLoad (if
	// any).
	OnUnload func(state interface{}) error
}

func (m Module) String() string { return m.Name }

// RegisterModule registers a module. Modules must call
// this function in the init phase of runtime.
func RegisterModule(mod Module) error {
	if mod.Name == "caddy" {
		return fmt.Errorf("modules cannot be named 'caddy'")
	}

	modulesMu.Lock()
	defer modulesMu.Unlock()

	if _, ok := modules[mod.Name]; ok {
		return fmt.Errorf("module already registered: %s", mod.Name)
	}
	modules[mod.Name] = mod
	return nil
}

// GetModule returns a module by its full name.
func GetModule(name string) (Module, error) {
	modulesMu.Lock()
	defer modulesMu.Unlock()

	m, ok := modules[name]
	if !ok {
		return Module{}, fmt.Errorf("module not registered: %s", name)
	}
	return m, nil
}

// GetModules returns all modules in the given scope/namespace.
// For example, a scope of "foo" returns modules named "foo.bar",
// "foo.loo", but not "bar", "foo.bar.loo", etc. An empty scope
// returns top-level modules, for example "foo" or "bar". Partial
// scopes are not matched (i.e. scope "foo.ba" does not match
// name "foo.bar").
//
// Because modules are registered to a map, the returned slice
// will be sorted to keep it deterministic.
func GetModules(scope string) []Module {
	modulesMu.Lock()
	defer modulesMu.Unlock()

	scopeParts := strings.Split(scope, ".")

	// handle the special case of an empty scope, which
	// should match only the top-level modules
	if len(scopeParts) == 1 && scopeParts[0] == "" {
		scopeParts = []string{}
	}

	var mods []Module
iterateModules:
	for name, m := range modules {
		modParts := strings.Split(name, ".")

		// match only the next level of nesting
		if len(modParts) != len(scopeParts)+1 {
			continue
		}

		// specified parts must be exact matches
		for i := range scopeParts {
			if modParts[i] != scopeParts[i] {
				continue iterateModules
			}
		}

		mods = append(mods, m)
	}

	// make return value deterministic
	sort.Slice(mods, func(i, j int) bool {
		return mods[i].Name < mods[j].Name
	})

	return mods
}

// Modules returns the names of all registered modules
// in ascending lexicographical order.
func Modules() []string {
	modulesMu.Lock()
	defer modulesMu.Unlock()

	var names []string
	for name := range modules {
		names = append(names, name)
	}

	sort.Strings(names)

	return names
}

// LoadModule decodes rawMsg into a new instance of mod and
// returns the value. If mod.New() does not return a pointer
// value, it is converted to one so that it is unmarshaled
// into the underlying concrete type. If mod.New is nil, an
// error is returned. If the module implements Validator or
// Provisioner interfaces, those methods are invoked to
// ensure the module is fully configured and valid before
// being used.
func LoadModule(name string, rawMsg json.RawMessage) (interface{}, error) {
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

	err = json.Unmarshal(rawMsg, &val)
	if err != nil {
		return nil, fmt.Errorf("decoding module config: %s: %v", mod.Name, err)
	}

	if prov, ok := val.(Provisioner); ok {
		err := prov.Provision()
		if err != nil {
			return nil, fmt.Errorf("provision %s: %v", mod.Name, err)
		}
	}

	if validator, ok := val.(Validator); ok {
		err := validator.Validate()
		if err != nil {
			return nil, fmt.Errorf("%s: invalid configuration: %v", mod.Name, err)
		}
	}

	moduleInstances[mod.Name] = append(moduleInstances[mod.Name], val)

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
func LoadModuleInline(moduleNameKey, moduleScope string, raw json.RawMessage) (interface{}, error) {
	moduleName, err := getModuleNameInline(moduleNameKey, raw)
	if err != nil {
		return nil, err
	}

	val, err := LoadModule(moduleScope+"."+moduleName, raw)
	if err != nil {
		return nil, fmt.Errorf("loading module '%s': %v", moduleName, err)
	}

	return val, nil
}

// getModuleNameInline loads the string value from raw of moduleNameKey,
// where raw must be a JSON encoding of a map.
func getModuleNameInline(moduleNameKey string, raw json.RawMessage) (string, error) {
	var tmp map[string]interface{}
	err := json.Unmarshal(raw, &tmp)
	if err != nil {
		return "", err
	}

	moduleName, ok := tmp[moduleNameKey].(string)
	if !ok || moduleName == "" {
		return "", fmt.Errorf("module name not specified with key '%s' in %+v", moduleNameKey, tmp)
	}

	return moduleName, nil
}

// Validator is implemented by modules which can verify that their
// configurations are valid. This method will be called after New()
// instantiations of modules (if implemented). Validation should
// always be fast (imperceptible running time) and an error should
// be returned only if the value's configuration is invalid.
type Validator interface {
	Validate() error
}

// Provisioner is implemented by modules which may need to perform
// some additional "setup" steps immediately after being loaded.
// This method will be called after Validate() (if implemented).
type Provisioner interface {
	Provision() error
}

var (
	modules   = make(map[string]Module)
	modulesMu sync.Mutex
)
