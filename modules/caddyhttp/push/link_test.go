// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package push

import (
	"reflect"
	"testing"
)

func TestParseLinkHeader(t *testing.T) {
	testCases := []struct {
		header            string
		expectedResources []linkResource
	}{
		{
			header:            "</resource>; as=script",
			expectedResources: []linkResource{{uri: "/resource", params: map[string]string{"as": "script"}}},
		},
		{
			header:            "</resource>",
			expectedResources: []linkResource{{uri: "/resource", params: map[string]string{}}},
		},
		{
			header:            "</resource>; nopush",
			expectedResources: []linkResource{{uri: "/resource", params: map[string]string{"nopush": "nopush"}}},
		},
		{
			header:            "</resource>;nopush;rel=next",
			expectedResources: []linkResource{{uri: "/resource", params: map[string]string{"nopush": "nopush", "rel": "next"}}},
		},
		{
			header: "</resource>;nopush;rel=next,</resource2>;nopush",
			expectedResources: []linkResource{
				{uri: "/resource", params: map[string]string{"nopush": "nopush", "rel": "next"}},
				{uri: "/resource2", params: map[string]string{"nopush": "nopush"}},
			},
		},
		{
			header: "</resource>,</resource2>",
			expectedResources: []linkResource{
				{uri: "/resource", params: map[string]string{}},
				{uri: "/resource2", params: map[string]string{}},
			},
		},
		{
			header:            "malformed",
			expectedResources: []linkResource{},
		},
		{
			header:            "<malformed",
			expectedResources: []linkResource{},
		},
		{
			header:            ",",
			expectedResources: []linkResource{},
		},
		{
			header:            ";",
			expectedResources: []linkResource{},
		},
		{
			header:            "</resource> ; ",
			expectedResources: []linkResource{{uri: "/resource", params: map[string]string{}}},
		},
	}

	for i, test := range testCases {
		actualResources := parseLinkHeader(test.header)
		if !reflect.DeepEqual(actualResources, test.expectedResources) {
			t.Errorf("Test %d (header: %s) - expected resources %v, got %v",
				i, test.header, test.expectedResources, actualResources)
		}
	}
}
