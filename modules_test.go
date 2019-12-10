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
		"a":      {ID: "a"},
		"a.b":    {ID: "a.b"},
		"a.b.c":  {ID: "a.b.c"},
		"a.b.cd": {ID: "a.b.cd"},
		"a.c":    {ID: "a.c"},
		"a.d":    {ID: "a.d"},
		"b":      {ID: "b"},
		"b.a":    {ID: "b.a"},
		"b.b":    {ID: "b.b"},
		"b.a.c":  {ID: "b.a.c"},
		"c":      {ID: "c"},
	}
	modulesMu.Unlock()

	for i, tc := range []struct {
		input  string
		expect []ModuleInfo
	}{
		{
			input: "",
			expect: []ModuleInfo{
				{ID: "a"},
				{ID: "b"},
				{ID: "c"},
			},
		},
		{
			input: "a",
			expect: []ModuleInfo{
				{ID: "a.b"},
				{ID: "a.c"},
				{ID: "a.d"},
			},
		},
		{
			input: "a.b",
			expect: []ModuleInfo{
				{ID: "a.b.c"},
				{ID: "a.b.cd"},
			},
		},
		{
			input: "a.b.c",
		},
		{
			input: "b",
			expect: []ModuleInfo{
				{ID: "b.a"},
				{ID: "b.b"},
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
