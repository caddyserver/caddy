package caddy2

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Module is a module.
type Module struct {
	Name string
	New  func() (interface{}, error)
}

func (m Module) String() string { return m.Name }

// RegisterModule registers a module.
func RegisterModule(mod Module) error {
	modulesMu.Lock()
	defer modulesMu.Unlock()

	if _, ok := modules[mod.Name]; ok {
		return fmt.Errorf("module already registered: %s", mod.Name)
	}
	modules[mod.Name] = mod
	return nil
}

// GetModule returns a module by name.
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
// "foo.lor", but not "bar", "foo.bar.lor", etc. An empty scope
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

var (
	modules   = make(map[string]Module)
	modulesMu sync.Mutex
)
