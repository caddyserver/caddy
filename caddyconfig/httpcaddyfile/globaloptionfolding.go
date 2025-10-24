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

package httpcaddyfile

import "fmt"

// GlobalOptionFolder defines how to fold/accumulate multiple instances of a global option.
// Some global options (like "servers", "log", "default_bind") can appear multiple times
// and need to be accumulated into a slice rather than being replaced.
type GlobalOptionFolder interface {
	// Fold combines the new value with any existing value, returning the accumulated result.
	// For example, it might append a single item to a slice, or merge two slices.
	Fold(existing, newVal any) (any, error)
}

// serverOptionsFolder handles folding for the "servers" global option
type serverOptionsFolder struct{}

func (serverOptionsFolder) Fold(existing, newVal any) (any, error) {
	existingOpts, _ := existing.([]ServerOptions)
	serverOpts, ok := newVal.(ServerOptions)
	if !ok {
		return nil, fmt.Errorf("unexpected type from 'servers' global options: %T", newVal)
	}
	return append(existingOpts, serverOpts), nil
}

// configValueSliceFolder handles folding for options that return []ConfigValue
type configValueSliceFolder struct {
	optionName string
}

func (f configValueSliceFolder) Fold(existing, newVal any) (any, error) {
	existingOpts, _ := existing.([]ConfigValue)
	newOpts, ok := newVal.([]ConfigValue)
	if !ok {
		return nil, fmt.Errorf("unexpected type from '%s' global options: %T", f.optionName, newVal)
	}
	return append(existingOpts, newOpts...), nil
}

// globalOptionFolders maps option names to their folder implementations
var globalOptionFolders = map[string]GlobalOptionFolder{
	"servers":      serverOptionsFolder{},
	"log":          configValueSliceFolder{optionName: "log"},
	"default_bind": configValueSliceFolder{optionName: "default_bind"},
}

// GetGlobalOptionFolder returns the folder for a global option if it supports folding.
// Returns nil if the option should use simple replacement instead.
func GetGlobalOptionFolder(opt string) GlobalOptionFolder {
	return globalOptionFolders[opt]
}
