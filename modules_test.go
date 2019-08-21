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
	"reflect"
	"testing"
)

func TestGetModules(t *testing.T) {
	modulesMu.Lock()
	modules = map[string]ModuleInfo{
		"a":      {Name: "a"},
		"a.b":    {Name: "a.b"},
		"a.b.c":  {Name: "a.b.c"},
		"a.b.cd": {Name: "a.b.cd"},
		"a.c":    {Name: "a.c"},
		"a.d":    {Name: "a.d"},
		"b":      {Name: "b"},
		"b.a":    {Name: "b.a"},
		"b.b":    {Name: "b.b"},
		"b.a.c":  {Name: "b.a.c"},
		"c":      {Name: "c"},
	}
	modulesMu.Unlock()

	for i, tc := range []struct {
		input  string
		expect []ModuleInfo
	}{
		{
			input: "",
			expect: []ModuleInfo{
				{Name: "a"},
				{Name: "b"},
				{Name: "c"},
			},
		},
		{
			input: "a",
			expect: []ModuleInfo{
				{Name: "a.b"},
				{Name: "a.c"},
				{Name: "a.d"},
			},
		},
		{
			input: "a.b",
			expect: []ModuleInfo{
				{Name: "a.b.c"},
				{Name: "a.b.cd"},
			},
		},
		{
			input: "a.b.c",
		},
		{
			input: "b",
			expect: []ModuleInfo{
				{Name: "b.a"},
				{Name: "b.b"},
			},
		},
		{
			input: "asdf",
		},
	} {
		actual := GetModules(tc.input)
		if !reflect.DeepEqual(actual, tc.expect) {
			t.Errorf("Test %d: Expected %v but got %v", i, tc.expect, actual)
		}
	}
}
