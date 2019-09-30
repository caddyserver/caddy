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
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Module is a type that is used as a Caddy module.
type Module interface {
	// This method indicates the type is a Caddy
	// module. The returned ModuleInfo must have
	// both a name and a constructor function.
	// This method must not have any side-effects.
	CaddyModule() ModuleInfo
}

// ModuleInfo represents a registered Caddy module.
type ModuleInfo struct {
	// Name is the full name of the module. It
	// must be unique and properly namespaced.
	Name string

	// New returns a pointer to a new, empty
	// instance of the module's type. The host
	// module which instantiates this module will
	// likely type-assert and invoke methods on
	// the returned value. This function must not
	// have any side-effects.
	New func() Module
}

// Namespace returns the module's namespace (scope)
// which is all but the last element of its name.
// If there is no explicit namespace in the name,
// the whole name is considered the namespace.
func (mi ModuleInfo) Namespace() string {
	lastDot := strings.LastIndex(mi.Name, ".")
	if lastDot < 0 {
		return mi.Name
	}
	return mi.Name[:lastDot]
}

// ID returns a module's ID, which is the
// last element of its name.
func (mi ModuleInfo) ID() string {
	if mi.Name == "" {
		return ""
	}
	parts := strings.Split(mi.Name, ".")
	return parts[len(parts)-1]
}

func (mi ModuleInfo) String() string { return mi.Name }

// RegisterModule registers a module by receiving a
// plain/empty value of the module. For registration to
// be properly recorded, this should be called in the
// init phase of runtime. Typically, the module package
// will do this as a side-effect of being imported.
// This function returns an error if the module's info
// is incomplete or invalid, or if the module is
// already registered.
func RegisterModule(instance Module) error {
	mod := instance.CaddyModule()

	if mod.Name == "" {
		return fmt.Errorf("missing ModuleInfo.Name")
	}
	if mod.Name == "caddy" || mod.Name == "admin" {
		return fmt.Errorf("module name '%s' is reserved", mod.Name)
	}
	if mod.New == nil {
		return fmt.Errorf("missing ModuleInfo.New")
	}
	if val := mod.New(); val == nil {
		return fmt.Errorf("ModuleInfo.New must return a non-nil module instance")
	}

	modulesMu.Lock()
	defer modulesMu.Unlock()

	if _, ok := modules[mod.Name]; ok {
		return fmt.Errorf("module already registered: %s", mod.Name)
	}
	modules[mod.Name] = mod
	return nil
}

// GetModule returns module information from its full name.
func GetModule(name string) (ModuleInfo, error) {
	modulesMu.Lock()
	defer modulesMu.Unlock()
	m, ok := modules[name]
	if !ok {
		return ModuleInfo{}, fmt.Errorf("module not registered: %s", name)
	}
	return m, nil
}

// GetModuleName returns a module's name from an instance of its value.
// If the value is not a module, an empty name will be returned.
func GetModuleName(instance interface{}) string {
	var name string
	if mod, ok := instance.(Module); ok {
		name = mod.CaddyModule().Name
	}
	return name
}

// GetModuleID returns a module's ID (the last element of its name)
// from an instance of its value. If the value is not a module,
// an empty string will be returned.
func GetModuleID(instance interface{}) string {
	var name string
	if mod, ok := instance.(Module); ok {
		name = mod.CaddyModule().ID()
	}
	return name
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
func GetModules(scope string) []ModuleInfo {
	modulesMu.Lock()
	defer modulesMu.Unlock()

	scopeParts := strings.Split(scope, ".")

	// handle the special case of an empty scope, which
	// should match only the top-level modules
	if scope == "" {
		scopeParts = []string{}
	}

	var mods []ModuleInfo
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
// where raw must be a JSON encoding of a map. It returns that value,
// along with the result of removing that key from raw.
func getModuleNameInline(moduleNameKey string, raw json.RawMessage) (string, json.RawMessage, error) {
	var tmp map[string]interface{}
	err := json.Unmarshal(raw, &tmp)
	if err != nil {
		return "", nil, err
	}

	moduleName, ok := tmp[moduleNameKey].(string)
	if !ok || moduleName == "" {
		return "", nil, fmt.Errorf("module name not specified with key '%s' in %+v", moduleNameKey, tmp)
	}

	// remove key from the object, otherwise decoding it later
	// will yield an error because the struct won't recognize it
	// (this is only needed because we strictly enforce that
	// all keys are recognized when loading modules)
	delete(tmp, moduleNameKey)
	result, err := json.Marshal(tmp)
	if err != nil {
		return "", nil, fmt.Errorf("re-encoding module configuration: %v", err)
	}

	return moduleName, result, nil
}

// Provisioner is implemented by modules which may need to perform
// some additional "setup" steps immediately after being loaded.
// Provisioning should be fast (imperceptible running time). If
// any side-effects result in the execution of this function (e.g.
// creating global state, any other allocations which require
// garbage collection, opening files, starting goroutines etc.),
// be sure to clean up properly by implementing the CleanerUpper
// interface to avoid leaking resources.
type Provisioner interface {
	Provision(Context) error
}

// Validator is implemented by modules which can verify that their
// configurations are valid. This method will be called after
// Provision() (if implemented). Validation should always be fast
// (imperceptible running time) and an error should be returned only
// if the value's configuration is invalid.
type Validator interface {
	Validate() error
}

// CleanerUpper is implemented by modules which may have side-effects
// such as opened files, spawned goroutines, or allocated some sort
// of non-stack state when they were provisioned. This method should
// deallocate/cleanup those resources to prevent memory leaks. Cleanup
// should be fast and efficient. Cleanup should work even if Provision
// returns an error, to allow cleaning up from partial provisionings.
type CleanerUpper interface {
	Cleanup() error
}

// strictUnmarshalJSON is like json.Unmarshal but returns an error
// if any of the fields are unrecognized. Useful when decoding
// module configurations, where you want to be more sure they're
// correct.
func strictUnmarshalJSON(data []byte, v interface{}) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

var (
	modules   = make(map[string]ModuleInfo)
	modulesMu sync.Mutex
)
