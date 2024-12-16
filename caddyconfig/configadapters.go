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

package caddyconfig

import (
	"encoding/json"
	"fmt"

	"github.com/caddyserver/caddy/v2"
)

// Adapter is a type which can adapt a configuration to Caddy JSON.
// It returns the results and any warnings, or an error.
type Adapter interface {
	Adapt(body []byte, options map[string]any) ([]byte, []Warning, error)
}

// Warning represents a warning or notice related to conversion.
type Warning struct {
	File      string `json:"file,omitempty"`
	Line      int    `json:"line,omitempty"`
	Directive string `json:"directive,omitempty"`
	Message   string `json:"message,omitempty"`
}

func (w Warning) String() string {
	var directive string
	if w.Directive != "" {
		directive = fmt.Sprintf(" (%s)", w.Directive)
	}
	return fmt.Sprintf("%s:%d%s: %s", w.File, w.Line, directive, w.Message)
}

// JSON encodes val as JSON, returning it as a json.RawMessage. Any
// marshaling errors (which are highly unlikely with correct code)
// are converted to warnings. This is convenient when filling config
// structs that require a json.RawMessage, without having to worry
// about errors.
func JSON(val any, warnings *[]Warning) json.RawMessage {
	b, err := json.Marshal(val)
	if err != nil {
		if warnings != nil {
			*warnings = append(*warnings, Warning{Message: err.Error()})
		}
		return nil
	}
	return b
}

// JSONModuleObject is like JSON(), except it marshals val into a JSON object
// with an added key named fieldName with the value fieldVal. This is useful
// for encoding module values where the module name has to be described within
// the object by a certain key; for example, `"handler": "file_server"` for a
// file server HTTP handler (fieldName="handler" and fieldVal="file_server").
// The val parameter must encode into a map[string]any (i.e. it must be
// a struct or map). Any errors are converted into warnings.
func JSONModuleObject(val any, fieldName, fieldVal string, warnings *[]Warning) json.RawMessage {
	// encode to a JSON object first
	enc, err := json.Marshal(val)
	if err != nil {
		if warnings != nil {
			*warnings = append(*warnings, Warning{Message: err.Error()})
		}
		return nil
	}

	// then decode the object
	var tmp map[string]any
	err = json.Unmarshal(enc, &tmp)
	if err != nil {
		if warnings != nil {
			*warnings = append(*warnings, Warning{Message: err.Error()})
		}
		return nil
	}

	// so we can easily add the module's field with its appointed value
	tmp[fieldName] = fieldVal

	// then re-marshal as JSON
	result, err := json.Marshal(tmp)
	if err != nil {
		if warnings != nil {
			*warnings = append(*warnings, Warning{Message: err.Error()})
		}
		return nil
	}

	return result
}

// RegisterAdapter registers a config adapter with the given name.
// This should usually be done at init-time. It panics if the
// adapter cannot be registered successfully.
func RegisterAdapter(name string, adapter Adapter) {
	if _, ok := configAdapters[name]; ok {
		panic(fmt.Errorf("%s: already registered", name))
	}
	configAdapters[name] = adapter
	caddy.RegisterModule(adapterModule{name, adapter})
}

// GetAdapter returns the adapter with the given name,
// or nil if one with that name is not registered.
func GetAdapter(name string) Adapter {
	return configAdapters[name]
}

// adapterModule is a wrapper type that can turn any config
// adapter into a Caddy module, which has the benefit of being
// counted with other modules, even though they do not
// technically extend the Caddy configuration structure.
// See caddyserver/caddy#3132.
type adapterModule struct {
	name string
	Adapter
}

func (am adapterModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  caddy.ModuleID("caddy.adapters." + am.name),
		New: func() caddy.Module { return am },
	}
}

var configAdapters = make(map[string]Adapter)
