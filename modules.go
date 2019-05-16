package caddy2

import (
	"encoding/json"
	"fmt"
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
	Validate(Context) error
}

// Provisioner is implemented by modules which may need to perform
// some additional "setup" steps immediately after being loaded.
// This method will be called after Validate() (if implemented).
type Provisioner interface {
	Provision(Context) error
}

// TODO: different name...
type CleanerUpper interface {
	Cleanup() error
}

var (
	modules   = make(map[string]Module)
	modulesMu sync.Mutex
)
