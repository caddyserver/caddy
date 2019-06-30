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

package caddyscript

import (
	"fmt"
	"regexp"

	"go.starlark.net/starlark"
)

// Regexp represents a regexp type for caddyscript.
type Regexp struct{}

// AttrNames defines what properties and methods are available on the Time type.
func (r Regexp) AttrNames() []string {
	return []string{"match_string"}
}

// Attr defines what happens when props or methods are called on the Time type.
func (r Regexp) Attr(name string) (starlark.Value, error) {
	switch name {
	case "match_string":
		b := starlark.NewBuiltin("match_string", r.MatchString)
		b = b.BindReceiver(r)
		return b, nil
	}

	return nil, nil
}

// MatchString reports whether the string s contains any match of the regular expression pattern. More complicated queries need to use Compile and the full Regexp interface.
func (r Regexp) MatchString(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var pattern, match string
	err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 2, &pattern, &match)
	if err != nil {
		return starlark.None, fmt.Errorf("could not unpack args: %v", err.Error())
	}

	matched, err := regexp.MatchString(pattern, match)
	if err != nil {
		return starlark.False, fmt.Errorf("matchstring: %v", err.Error())
	}

	return starlark.Bool(matched), nil
}

func (r Regexp) Freeze()               {}
func (r Regexp) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: Regexp") }
func (r Regexp) String() string        { return "Regexp" }
func (r Regexp) Type() string          { return "Regexp" }
func (r Regexp) Truth() starlark.Bool  { return true }
